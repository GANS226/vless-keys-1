"""Пинг до серверов ключей из Москвы и Беларуси через Globalping (https://globalping.io).

Сервер бота стоит за границей, а пользователи — в СНГ. Globalping даёт бесплатно мерить
TCP-пинг с их точек в разных городах. Без токена — 250 замеров в час с одного IP
(один замер = одна точка), с бесплатным токеном — больше.
"""
import asyncio
import logging

import aiohttp

log = logging.getLogger(__name__)

API = "https://api.globalping.io/v1/measurements"
# Откуда меряем: ключ словаря — подпись, значение — фильтр точки Globalping
LOCATIONS = {
    "Москва": {"country": "RU", "city": "Moscow"},
    "Беларусь": {"country": "BY"},
}
MOSCOW_ONLY = {"Москва": LOCATIONS["Москва"]}


class Globalping:
    def __init__(self, session: aiohttp.ClientSession, token: str | None = None):
        self._session = session
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}

    async def tcp_ping(
        self, targets: list[tuple[str, int]], locations: dict[str, dict] | None = None
    ) -> dict[tuple[str, int], dict[str, float | None]]:
        """{(хост, порт): {"Москва": мс или None, "Беларусь": ...}}. None — сервер оттуда не отвечает.
        Если цели нет в ответе, замер не получился (например, кончился лимит).
        locations — откуда мерить (по умолчанию LOCATIONS); каждая точка — один замер из лимита."""
        locations = locations or LOCATIONS
        ids: dict[tuple[str, int], str] = {}
        for target in dict.fromkeys(targets):
            measurement_id = await self._start(target, locations)
            if measurement_id is None:
                break  # лимит или сбой — остальные не запускаем
            ids[target] = measurement_id
        if not ids:
            return {}

        await asyncio.sleep(3)
        results = await asyncio.gather(*(self._result(mid, locations) for mid in ids.values()))
        return {t: r for t, r in zip(ids, results) if r is not None}

    async def _start(self, target: tuple[str, int], locations: dict[str, dict]) -> str | None:
        host, port = target
        body = {
            "type": "ping",
            "target": host,
            "locations": [{**loc, "limit": 1} for loc in locations.values()],
            "measurementOptions": {"packets": 3, "protocol": "TCP", "port": port},
        }
        try:
            async with self._session.post(API, json=body, headers=self._headers) as resp:
                if resp.status == 429:
                    log.warning("Globalping: кончился лимит замеров на этот час")
                    return None
                data = await resp.json(content_type=None)
                if resp.status != 202:
                    log.info("Globalping не принял %s: %s", host, data)
                    # Например, цель — частный адрес. Пропускаем её, но не останавливаемся
                    return ""
                return data["id"]
        except Exception as e:
            log.warning("Globalping недоступен: %s", e)
            return None

    async def _result(self, measurement_id: str, locations: dict[str, dict]) -> dict[str, float | None] | None:
        if not measurement_id:
            return None
        for _ in range(15):
            try:
                async with self._session.get(f"{API}/{measurement_id}") as resp:
                    data = await resp.json(content_type=None)
            except Exception:
                data = {}
            if data.get("status") == "finished":
                return self._parse(data, locations)
            await asyncio.sleep(2)
        return None

    @staticmethod
    def _parse(data: dict, locations: dict[str, dict]) -> dict[str, float | None]:
        pings: dict[str, float | None] = {}
        for item in data.get("results", []):
            probe, result = item.get("probe", {}), item.get("result", {})
            for name, loc in locations.items():
                if probe.get("country") == loc["country"] and name not in pings:
                    stats = result.get("stats") or {}
                    alive = result.get("status") == "finished" and stats.get("loss", 100) < 100
                    pings[name] = stats.get("avg") if alive else None
                    break
        return pings
