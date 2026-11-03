"""Источники бесплатных ключей (SOURCES) и SOCKS5-прокси для Telegram (PROXY_SOURCES).
Чтобы добавить источник — допиши строку в нужный список."""
import asyncio
import base64
import html
import logging
import random
import re
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from services.links import LINK_RE

log = logging.getLogger(__name__)

PROJECT_DIR = Path(__file__).resolve().parent.parent

HEADERS = {"User-Agent": "vless_for_me_bot (+https://t.me/vless_for_me_bot)"}
REQUEST_TIMEOUT = 15  # одна страница
SOURCE_TIMEOUT = 45  # весь источник целиком
SOCKS_RE = re.compile(r"socks5?://[^\s\"'<>\\`#]+")


@dataclass
class Source:
    name: str
    url: str
    # text — список ссылок (обычный или base64), vlesskey — сайт vlesskey.com,
    # file — файл рядом с кодом (url — путь от корня проекта),
    # hostport — список «IP:порт» без схемы (для SOCKS5-прокси)
    kind: str = "text"
    # Сколько ключей брать за раз (у больших списков — случайная выборка, каждый раз новая)
    limit: int | None = None


GH = "https://raw.githubusercontent.com"
OPENRAY = f"{GH}/sakha1370/OpenRay/main/output/kind"
SOURCES = [
    # Свои проверенные ключи (например, из проверки на ПК) — просто список ссылок
    Source("свои ключи", "extra_keys.txt", kind="file"),
    Source("vless-checker", "https://tiagorrg.github.io/vless-checker/keys.json"),
    # Большой сборник, живых среди них мало — отсеет проверка
    Source("OpenRay-vless", f"{OPENRAY}/vless.txt"),
    Source("OpenRay-trojan", f"{OPENRAY}/trojan.txt"),
    Source("OpenRay-vmess", f"{OPENRAY}/vmess.txt"),
    Source("OpenRay-ss", f"{OPENRAY}/ss.txt"),
    Source("igareck", f"{GH}/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt"),
    Source("igareck-mobile", f"{GH}/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt"),
    Source("grisha-seleznev", f"{GH}/grisha-seleznev/free-vless-keys-russia/main/sub.txt"),
    Source("slxkware", f"{GH}/slxkware/Vless-list/main/Black%20Vless.txt"),
    Source("kort0881", f"{GH}/kort0881/vpn-vless-configs-russia/main/output/vless.txt", limit=300),
    Source("vlesskey.com", "https://vlesskey.com", kind="vlesskey"),
]

PROXY_SOURCES = [
    Source("свои прокси", "extra_proxies.txt", kind="file"),
    Source("OpenRay", f"{OPENRAY}/socks.txt"),
    Source("monosans", f"{GH}/monosans/proxy-list/main/proxies/socks5.txt", kind="hostport"),
    Source("proxifly", f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", limit=1500),
]


def extract_links(text: str, regex: re.Pattern = LINK_RE) -> list[str]:
    text = html.unescape(text)
    found = regex.findall(text)
    if not found:
        # Подписки часто отдают в base64
        try:
            compact = re.sub(r"\s", "", text)
            text = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "replace")
        except ValueError:
            return []
        found = regex.findall(text)
    return [m.rstrip(".,;)") for m in found]


def extract_hostport(text: str) -> list[str]:
    return [f"socks5://{m}" for m in re.findall(r"^\s*(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})\s*$", text, re.M)]


class Collector:
    def __init__(self, session: aiohttp.ClientSession, vlesskey_pages: int = 3):
        self._session = session
        self._vlesskey_pages = vlesskey_pages
        # vlesskey.com: номер ключа -> ссылка (страницу ключа качаем один раз)
        self._vlesskey_cache: dict[int, str | None] = {}
        # Сколько раз страница ключа не загрузилась; после 2 раз больше не пробуем
        self._vlesskey_failures: dict[int, int] = {}
        self._vlesskey_ids: list[int] = []  # номера ключей с последних просмотренных страниц

    async def collect(self) -> list[str]:
        """Все уникальные ключи из всех источников."""
        return await self._collect(SOURCES, LINK_RE, "ключей")

    async def collect_proxies(self) -> list[str]:
        """Все уникальные SOCKS5-прокси (ссылки socks5://...)."""
        return await self._collect(PROXY_SOURCES, SOCKS_RE, "прокси")

    async def _collect(self, sources: list[Source], regex: re.Pattern, what: str) -> list[str]:
        results = await asyncio.gather(*(self._fetch_limited(s, regex) for s in sources), return_exceptions=True)
        unique: dict[str, str] = {}
        stats = []
        for src, links in zip(sources, results):
            if isinstance(links, BaseException):
                log.warning("Источник %s недоступен: %s", src.name, links)
                stats.append(f"{src.name}=ошибка")
                continue
            if src.limit and len(links) > src.limit:
                links = random.sample(links, src.limit)
            stats.append(f"{src.name}={len(links)}")
            for url in links:
                # Один и тот же сервер с разными подписями (#...) считаем одним ключом
                unique.setdefault(url.split("#")[0], url)
        log.info("Собрано %s: %d (%s)", what, len(unique), ", ".join(stats))
        return list(unique.values())

    async def _get_text(self, url: str, timeout_s: float = REQUEST_TIMEOUT) -> str:
        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with self._session.get(url, headers=HEADERS, timeout=timeout) as resp:
            resp.raise_for_status()
            return await resp.text(errors="replace")

    async def _fetch_limited(self, src: Source, regex: re.Pattern) -> list[str]:
        """Медленный источник не должен задерживать остальные: ждём его не дольше SOURCE_TIMEOUT."""
        try:
            return await asyncio.wait_for(self._fetch(src, regex), SOURCE_TIMEOUT)
        except asyncio.TimeoutError:
            if src.kind == "vlesskey":
                # Что успели загрузить — берём
                log.info("vlesskey.com: не успел целиком, беру загруженное")
                return self._vlesskey_known()
            raise TimeoutError(f"не ответил за {SOURCE_TIMEOUT} с")

    async def _fetch(self, src: Source, regex: re.Pattern) -> list[str]:
        if src.kind == "vlesskey":
            return await self._fetch_vlesskey(src.url)
        if src.kind == "file":
            path = PROJECT_DIR / src.url
            return extract_links(path.read_text(encoding="utf-8-sig"), regex) if path.exists() else []
        # Большие списки (несколько МБ) качаются дольше одной страницы
        text = await self._get_text(src.url, timeout_s=SOURCE_TIMEOUT)
        return extract_hostport(text) if src.kind == "hostport" else extract_links(text, regex)

    def _vlesskey_known(self) -> list[str]:
        return [url for i in self._vlesskey_ids if (url := self._vlesskey_cache.get(i))]

    async def _fetch_vlesskey(self, base: str) -> list[str]:
        # На страницах списка только номера ключей, сама ссылка — на странице ключа
        ids: list[int] = []
        for page in range(1, self._vlesskey_pages + 1):
            text = await self._get_text(f"{base}/?page={page}")
            ids += [int(i) for i in re.findall(r"/key/(\d+)/", text)]
        self._vlesskey_ids = list(dict.fromkeys(ids))

        sem = asyncio.Semaphore(3)  # не нагружаем чужой сайт

        async def load(key_id: int) -> None:
            async with sem:
                try:
                    links = extract_links(await self._get_text(f"{base}/key/{key_id}/"))
                    self._vlesskey_cache[key_id] = links[0] if links else None
                except Exception as e:
                    self._vlesskey_failures[key_id] = self._vlesskey_failures.get(key_id, 0) + 1
                    log.info("vlesskey.com: ключ %d не загрузился: %s", key_id, type(e).__name__)

        todo = [
            i for i in self._vlesskey_ids
            if i not in self._vlesskey_cache and self._vlesskey_failures.get(i, 0) < 2
        ]
        await asyncio.gather(*(load(i) for i in todo))
        return self._vlesskey_known()
