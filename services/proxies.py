"""SOCKS5-прокси для Telegram: разбор, проверка и ссылка для подключения в один клик.

Telegram сам умеет работать через SOCKS5: ссылка https://t.me/socks?server=...&port=...
открывает окно «Подключить прокси». Прокси годится, если через него:
- открывается соединение с сервером Telegram (тем же, к которому ходит приложение);
- открываются api.telegram.org и web.telegram.org;
- выход в интернет — не из России (там Telegram и так заблокирован).
"""
import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from urllib.parse import unquote, urlencode

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType
from python_socks.async_.asyncio import Proxy as SocksProxy

from services.checker import TRACE_URL, tcp_sort

log = logging.getLogger(__name__)

# Сервер Telegram (DC2), к которому подключается приложение
TELEGRAM_DC = ("149.154.167.51", 443)
TELEGRAM_URLS = ("https://api.telegram.org/", "https://web.telegram.org/")


@dataclass(frozen=True)
class Socks:
    host: str
    port: int
    user: str = ""
    password: str = ""

    @property
    def tg_link(self) -> str:
        params = {"server": self.host, "port": self.port}
        if self.user:
            params.update(user=self.user, **{"pass": self.password})
        return "https://t.me/socks?" + urlencode(params)


@dataclass
class ProxyProbe:
    latency_ms: float
    country: str


def parse_socks(url: str) -> Socks | None:
    """socks5://[логин:пароль@]хост:порт (логин:пароль бывает в base64)."""
    try:
        body = url.split("://", 1)[1].split("#", 1)[0].split("?", 1)[0].rstrip("/")
        userinfo, _, hostport = body.rpartition("@")
        host, _, port = hostport.rpartition(":")
        host = host.strip("[]")
        if not host or not port.isdigit() or not 0 < int(port) < 65536:
            return None
        user = password = ""
        if userinfo:
            userinfo = unquote(userinfo)
            if ":" not in userinfo:
                userinfo = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
            user, _, password = userinfo.partition(":")
        return Socks(host, int(port), user, password)
    except (ValueError, UnicodeDecodeError):
        return None


class ProxyChecker:
    def __init__(self, timeout: float = 10, concurrency: int = 60, trace_url: str = TRACE_URL,
                 telegram_dc: tuple[str, int] = TELEGRAM_DC, telegram_urls: tuple[str, ...] = TELEGRAM_URLS):
        self._timeout = timeout
        self._concurrency = concurrency
        self._trace_url = trace_url
        self._telegram_dc = telegram_dc
        self._telegram_urls = telegram_urls

    async def precheck(self, proxies: list[Socks]) -> list[Socks]:
        """Отсеивает прокси с закрытым портом; самые отзывчивые — первыми."""
        return await tcp_sort(proxies, lambda p: (p.host, p.port), concurrency=200)

    async def check(self, proxies: list[Socks]) -> dict[Socks, ProxyProbe]:
        sem = asyncio.Semaphore(self._concurrency)

        async def one(p: Socks) -> tuple[Socks, ProxyProbe | None]:
            async with sem:
                try:
                    return p, await asyncio.wait_for(self._probe(p), self._timeout * 3)
                except Exception:
                    return p, None

        results = await asyncio.gather(*(one(p) for p in proxies))
        return {p: r for p, r in results if r}

    async def _probe(self, p: Socks) -> ProxyProbe | None:
        # 1. Соединение с сервером Telegram через прокси (настоящий SOCKS5 отвечает «успех»
        #    только после того, как сам подключился к цели)
        socks = SocksProxy(ProxyType.SOCKS5, p.host, p.port, p.user or None, p.password or None)
        sock = await socks.connect(*self._telegram_dc, timeout=self._timeout)
        sock.close()

        connector = ProxyConnector(
            proxy_type=ProxyType.SOCKS5, host=p.host, port=p.port,
            username=p.user or None, password=p.password or None, rdns=True,
        )
        async with aiohttp.ClientSession(
            connector=connector, timeout=aiohttp.ClientTimeout(total=self._timeout)
        ) as session:
            # 2. Страна выхода и пинг: первый запрос открывает соединение, второй — чистый пинг
            async with session.get(self._trace_url) as resp:
                text = await resp.text()
            start = time.monotonic()
            async with session.get(self._trace_url) as resp:
                await resp.read()
            latency = (time.monotonic() - start) * 1000
            # 3. Сайты Telegram (любой HTTP-ответ — значит, открывается)
            for url in self._telegram_urls:
                async with session.get(url, allow_redirects=False) as resp:
                    if not resp.status:
                        return None
        fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        return ProxyProbe(latency, fields["loc"].upper()) if "loc" in fields else None
