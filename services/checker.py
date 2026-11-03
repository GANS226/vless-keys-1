"""Настоящая проверка ключей (VLESS, VMess, Trojan, Shadowsocks) через Xray.

Один процесс Xray на пачку ключей: у каждого ключа свой локальный SOCKS-порт (20000, 20001, ...),
трафик с порта уходит в «свой» outbound. Через порт делаем обычные HTTP-запросы:
- пинг и страна выхода — запрос к Cloudflare trace (он отвечает, из какой страны пришёл запрос);
- открываются ли Telegram, Instagram, Discord, TikTok;
- скорость — скачивание файла с speed.cloudflare.com.
"""
import asyncio
import json
import logging
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

from services.links import entry_point, link_to_outbound

log = logging.getLogger(__name__)

TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
SPEED_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"
# Ради этих сервисов люди и ставят VPN. Ключ годится, только если открываются все.
# api.telegram.org стоит в той же сети, что и серверы приложения Telegram.
SERVICES = {
    "Telegram": "https://api.telegram.org/",
    "Telegram Web": "https://web.telegram.org/",
    "Instagram": "https://www.instagram.com/",
    "Discord": "https://discord.com/api/v10/gateway",
    "TikTok": "https://www.tiktok.com/",
}


async def tcp_sort(items: list, address, timeout: float = 3, concurrency: int = 100) -> list:
    """Оставляет элементы, чей сервер принимает TCP-соединение; самые отзывчивые — первыми.
    address(item) -> (хост, порт) или None, если адрес не разобрать."""
    sem = asyncio.Semaphore(concurrency)

    async def connect(item) -> tuple[object, float] | None:
        target = address(item)
        if not target:
            return None
        async with sem:
            start = time.monotonic()
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(*target), timeout)
                writer.close()
                return item, time.monotonic() - start
            except (OSError, asyncio.TimeoutError):
                return None

    alive = [r for r in await asyncio.gather(*(connect(i) for i in items)) if r]
    alive.sort(key=lambda r: r[1])
    return [item for item, _ in alive]


@dataclass
class Probe:
    latency_ms: float
    country: str  # двухбуквенный код страны выхода, например DE
    failed: list[str] = field(default_factory=list)  # сервисы, которые не открылись


class KeyChecker:
    def __init__(
        self,
        xray_path: Path,
        timeout: float = 10,
        concurrency: int = 25,
        base_port: int = 20000,
        trace_url: str = TRACE_URL,
        speed_url: str = SPEED_URL,
        services: dict[str, str] | None = None,
    ):
        self._xray_path = xray_path
        self._timeout = timeout
        self._concurrency = concurrency
        self._base_port = base_port
        self._trace_url = trace_url
        self._speed_url = speed_url
        self._services_urls = SERVICES if services is None else services

    # ---------- этап 1: открыт ли порт сервера ----------

    async def tcp_precheck(self, urls: list[str]) -> list[str]:
        """Отсеивает ключи, у которых сервер даже не принимает соединение. Самые отзывчивые — первыми."""

        def address(url: str) -> tuple[str, int] | None:
            try:
                return entry_point(url)
            except (ValueError, json.JSONDecodeError):
                return None

        return await tcp_sort(urls, address)

    # ---------- этап 2: пинг, страна выхода и нужные сервисы ----------

    async def probe(self, urls: list[str]) -> dict[str, Probe]:
        """Для каждого ключа: работает ли он вообще, пинг, страна выхода и какие сервисы не открылись."""
        async with self._xray(urls) as ports:
            sem = asyncio.Semaphore(self._concurrency)

            async def probe_one(url: str, port: int) -> tuple[str, Probe | None]:
                async with sem:
                    result = await self._trace(port)
                    if result:
                        result.failed = await self._services(port)
                    return url, result

            results = await asyncio.gather(*(probe_one(u, p) for u, p in ports.items()))
        return {url: p for url, p in results if p}

    async def _services(self, port: int) -> list[str]:
        """Открываем сайты сервисов через ключ. Любой HTTP-ответ = сервис доступен."""

        async def status(session: aiohttp.ClientSession, url: str) -> int:
            async with session.get(url, allow_redirects=False) as resp:
                return resp.status

        async def opens(session: aiohttp.ClientSession, url: str) -> bool:
            for _ in range(2):
                try:
                    # Свой лимит времени: таймаут aiohttp не всегда срабатывает на этапе SOCKS
                    return await asyncio.wait_for(status(session, url), self._timeout) > 0
                except Exception:
                    pass
            return False

        async with self._session(port) as session:
            ok = await asyncio.gather(*(opens(session, url) for url in self._services_urls.values()))
        return [name for name, good in zip(self._services_urls, ok) if not good]

    async def _trace(self, port: int) -> Probe | None:
        async def attempt() -> Probe | None:
            async with self._session(port) as session:
                # Первый запрос устанавливает туннель, второй (по тому же соединению) — чистый пинг
                async with session.get(self._trace_url) as resp:
                    text = await resp.text()
                start = time.monotonic()
                async with session.get(self._trace_url) as resp:
                    await resp.read()
                latency = (time.monotonic() - start) * 1000
            fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
            return Probe(latency, fields["loc"].upper()) if "loc" in fields else None

        for _ in range(2):  # вторая попытка — на случай случайного сбоя
            try:
                result = await asyncio.wait_for(attempt(), self._timeout)
                if result:
                    return result
            except Exception:
                pass
        return None

    # ---------- этап 3: скорость ----------

    async def probe_speed(self, urls: list[str], size_bytes: int, concurrency: int = 4) -> dict[str, float]:
        """Скорость скачивания в Мбит/с. Мало параллельных замеров, чтобы они не мешали друг другу."""
        url_template = self._speed_url.format(bytes=size_bytes)
        async with self._xray(urls) as ports:
            sem = asyncio.Semaphore(concurrency)

            async def download(port: int) -> float | None:
                async with self._session(port, timeout=20) as session:
                    start = time.monotonic()
                    async with session.get(url_template) as resp:
                        got = len(await resp.read())
                    elapsed = time.monotonic() - start
                if resp.status == 200 and got >= size_bytes * 0.9:
                    return got * 8 / elapsed / 1e6
                return None

            async def measure(url: str, port: int) -> tuple[str, float | None]:
                async with sem:
                    try:
                        return url, await asyncio.wait_for(download(port), 20)
                    except Exception:
                        return url, None

            results = await asyncio.gather(*(measure(u, p) for u, p in ports.items()))
        return {url: mbps for url, mbps in results if mbps is not None}

    # ---------- общее ----------

    def _session(self, port: int, timeout: float | None = None) -> aiohttp.ClientSession:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}", rdns=True)
        return aiohttp.ClientSession(
            connector=connector, timeout=aiohttp.ClientTimeout(total=timeout or self._timeout)
        )

    @asynccontextmanager
    async def _xray(self, urls: list[str]):
        """Запускает Xray для пачки ключей, отдаёт {ключ: локальный порт}."""
        entries = []
        for url in urls:
            try:
                entries.append((url, link_to_outbound(url, "x")))
            except (ValueError, json.JSONDecodeError) as e:
                log.debug("Пропускаю ключ: %s", e)

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "check.json"
            proc = await self._start(entries, config_path)
            if proc is None and entries:
                # Xray не принял общий конфиг — выкидываем ключи, которые он не понимает, и пробуем снова
                entries = await self._only_valid(entries, Path(tmp))
                proc = await self._start(entries, config_path)
            try:
                yield {url: self._base_port + i for i, (url, _) in enumerate(entries)} if proc else {}
            finally:
                if proc:
                    await self._stop(proc)

    def _build_config(self, entries: list[tuple[str, dict]]) -> dict:
        inbounds, outbounds, rules = [], [], []
        for i, (_, outbound) in enumerate(entries):
            inbounds.append({
                "tag": f"in{i}",
                "listen": "127.0.0.1",
                "port": self._base_port + i,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            })
            outbounds.append({**outbound, "tag": f"out{i}"})
            rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
        return {
            "log": {"loglevel": "none"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"rules": rules},
        }

    async def _start(self, entries, config_path: Path) -> asyncio.subprocess.Process | None:
        if not entries:
            return None
        config_path.write_text(json.dumps(self._build_config(entries)), encoding="utf-8")
        proc = await asyncio.create_subprocess_exec(
            str(self._xray_path), "run", "-c", str(config_path),
            # Ошибки Xray пишет в stdout
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
        # Ждём, пока Xray откроет последний порт
        last_port = self._base_port + len(entries) - 1
        for _ in range(100):
            if proc.returncode is not None:
                err = (await proc.stdout.read()).decode(errors="replace")
                log.warning("Xray не запустился: %s", err.strip()[-500:])
                return None
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", last_port)
                writer.close()
                return proc
            except OSError:
                await asyncio.sleep(0.1)
        log.warning("Xray не открыл порты за 10 секунд")
        await self._stop(proc)
        return None

    async def _only_valid(self, entries, tmp: Path) -> list:
        sem = asyncio.Semaphore(8)

        async def is_valid(i: int, outbound: dict) -> bool:
            path = tmp / f"one{i}.json"
            path.write_text(json.dumps({"outbounds": [outbound]}), encoding="utf-8")
            async with sem:
                proc = await asyncio.create_subprocess_exec(
                    str(self._xray_path), "run", "-test", "-c", str(path),
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                return await proc.wait() == 0

        ok = await asyncio.gather(*(is_valid(i, o) for i, (_, o) in enumerate(entries)))
        valid = [e for e, good in zip(entries, ok) if good]
        log.info("Xray понимает %d ключей из %d", len(valid), len(entries))
        return valid

    @staticmethod
    async def _stop(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
