"""Одна проверка: ключи (VLESS, VMess, Trojan, Shadowsocks) и SOCKS5-прокси для Telegram.
Результат — site/keys.json.

Запускается GitHub Actions каждые 30 минут (.github/workflows/check.yml).
Бот (Cloudflare Worker) только читает готовый keys.json.

Локально: python tools/get_xray.py && python check.py
"""
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

from services import keys_source
from services.checker import SERVICES, KeyChecker
from services.globalping import LOCATIONS, MOSCOW_ONLY, Globalping
from services.keys_source import CheckSettings, KeysSource, VlessKey, country_title
from services.links import PROTOCOLS, protocol_of, with_label
from services.proxies import ProxyChecker, Socks, parse_socks
from services.sources import Collector

BASE_DIR = Path(__file__).resolve().parent
XRAY_PATH = BASE_DIR / "bin" / ("xray.exe" if os.name == "nt" else "xray")
OUT_PATH = BASE_DIR / "site" / "keys.json"

log = logging.getLogger("check")


def env_int(name: str, default: int) -> int:
    return int(os.getenv(name) or default)


def key_json(key: VlessKey) -> dict:
    label = f"{country_title(key.country)} #{key.rank}" if key.country else f"#{key.rank}"
    protocol = protocol_of(key.url)
    return {
        "url": key.url,
        # Ключ с нашей подписью вместо чужой (подпись — это только название в приложении)
        "display": with_label(key.url, label),
        "protocol": protocol,
        "protocol_title": PROTOCOLS.get(protocol, protocol),
        "rank": key.rank,
        "country": key.country,
        "country_title": country_title(key.country) if key.country else None,
        "latency_ms": round(key.latency_ms) if key.latency_ms is not None else None,
        "speed_mbps": round(key.speed_mbps, 1) if key.speed_mbps is not None else None,
        "user_pings": {city: (round(v) if v is not None else None) for city, v in key.user_pings.items()},
    }


async def check_proxies(session: aiohttp.ClientSession, collector: Collector, globalping: Globalping) -> list[dict]:
    """SOCKS5-прокси, через которые работает Telegram и которые доступны из Москвы. Лучшие — первыми."""
    started = time.monotonic()
    parsed = {p for url in await collector.collect_proxies() if (p := parse_socks(url))}
    checker = ProxyChecker()
    alive = (await checker.precheck(list(parsed)))[: env_int("PROXY_MAX_CANDIDATES", 600)]
    log.info("Прокси: порт открыт у %d из %d (%.0f с)", len(alive), len(parsed), time.monotonic() - started)

    probes = await checker.check(alive)
    good = sorted(
        ((p, r) for p, r in probes.items() if r.country not in keys_source.EXCLUDED_EXITS),
        key=lambda pr: pr[1].latency_ms,
    )
    log.info("Прокси: Telegram работает через %d, из них выход не в РФ: %d (%.0f с)",
             len(probes), len(good), time.monotonic() - started)

    # Пинг из Москвы — только у лучших (каждый замер тратит лимит Globalping)
    top = good[: env_int("PROXY_PING_TOP", 20)]
    pings = await globalping.tcp_ping([(p.host, p.port) for p, _ in top], MOSCOW_ONLY)
    result = []
    for p, r in top:
        moscow = pings.get((p.host, p.port), {}).get("Москва", "нет замера")
        if moscow is None:
            continue  # из Москвы не достучаться — у пользователей тоже не заработает
        result.append({
            "link": p.tg_link,
            "country": r.country,
            "country_title": country_title(r.country),
            "latency_ms": round(r.latency_ms),
            "moscow_ping": round(moscow) if isinstance(moscow, (int, float)) else None,
        })
    # Сначала замеренные из Москвы, по пингу оттуда
    result.sort(key=lambda x: (x["moscow_ping"] is None, x["moscow_ping"] or x["latency_ms"]))
    log.info("Прокси: в выдаче %d (%.0f с)", len(result), time.monotonic() - started)
    return result


async def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not XRAY_PATH.exists():
        log.error("Нет %s — сначала python tools/get_xray.py", XRAY_PATH)
        return 1

    settings = CheckSettings(
        max_candidates=env_int("CHECK_MAX_CANDIDATES", 400),
        speed_top=env_int("SPEED_TOP", 30),
        speed_bytes=env_int("SPEED_BYTES", 500_000),
        user_ping_top=env_int("USER_PING_TOP", 50),
    )
    started = time.time()
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
        collector = Collector(session)
        globalping = Globalping(session, os.getenv("GLOBALPING_TOKEN") or None)
        source = KeysSource(collector, KeyChecker(XRAY_PATH), globalping,
                            refresh_seconds=0, report_limit=0, settings=settings)
        await source._refresh()
        data = source._data
        try:
            proxies = await check_proxies(session, collector, globalping)
        except Exception:
            log.exception("Проверка прокси не удалась — публикую без прокси")
            proxies = []

    if data is None or not data.total:
        # Не перезаписываем прошлый keys.json пустым: шаг публикации не запустится
        log.error("Ни одного рабочего ключа — результат не публикую")
        return 1

    result = {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "checked_at_ts": int(time.time()),
        "check_seconds": int(time.time() - started),
        "total": data.total,
        "services": [name for name in SERVICES if name != "Telegram Web"],
        "locations": list(LOCATIONS),
        "groups": [
            {"id": g.id, "title": g.title, "keys": [key_json(k) for k in g.keys]}
            for g in data.groups
            if g.keys
        ],
        "proxies": proxies,
    }
    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    log.info("Записал %s: %d ключей, %d групп, %d прокси", OUT_PATH, data.total, len(result["groups"]), len(proxies))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
