"""Сбор ключей из всех источников, проверка, рейтинг и группировка по странам."""
import asyncio
import logging
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace

from services.checker import KeyChecker, Probe
from services.globalping import Globalping
from services.sources import Collector
from services.links import entry_point

log = logging.getLogger(__name__)

BEST_ID = "best"
OTHER_ID = "cc.other"
# Выход в этих странах не помогает обходить блокировки — такие ключи не показываем
EXCLUDED_EXITS = {"RU"}
# Если отсюда сервер ключа не отвечает — значит, он заблокирован у основной аудитории, выкидываем
MAIN_LOCATION = "Москва"

COUNTRY_NAMES = {
    "DE": "Германия", "NL": "Нидерланды", "FI": "Финляндия", "SE": "Швеция", "PL": "Польша",
    "LT": "Литва", "LV": "Латвия", "EE": "Эстония", "FR": "Франция", "GB": "Великобритания",
    "US": "США", "CA": "Канада", "TR": "Турция", "MD": "Молдова", "SG": "Сингапур", "JP": "Япония",
    "KZ": "Казахстан", "AE": "ОАЭ", "IE": "Ирландия", "AT": "Австрия", "CH": "Швейцария",
    "CZ": "Чехия", "ES": "Испания", "IT": "Италия", "HK": "Гонконг", "BG": "Болгария",
    "RO": "Румыния", "UA": "Украина", "AM": "Армения", "GE": "Грузия", "RS": "Сербия",
    "NO": "Норвегия", "DK": "Дания", "BE": "Бельгия", "PT": "Португалия", "HU": "Венгрия",
    "IL": "Израиль", "IN": "Индия", "BR": "Бразилия", "AU": "Австралия", "KR": "Корея",
    "LU": "Люксембург", "IS": "Исландия", "BY": "Беларусь", "UZ": "Узбекистан", "CY": "Кипр",
}


def country_title(code: str) -> str:
    flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code) if len(code) == 2 and code.isalpha() else "🌐"
    return f"{flag} {COUNTRY_NAMES.get(code, code)}"


@dataclass
class VlessKey:
    url: str
    latency_ms: float | None = None  # пинг с сервера бота (через ключ)
    speed_mbps: float | None = None
    country: str | None = None
    # Пинг до сервера ключа из городов пользователей: {"Москва": 45.0, "Беларусь": 52.0}
    user_pings: dict[str, float | None] = field(default_factory=dict)
    rank: int = 0  # место в общем рейтинге (1 — лучший)

    @property
    def user_ping(self) -> float | None:
        values = [v for v in self.user_pings.values() if v is not None]
        return sum(values) / len(values) if values else None


@dataclass
class Group:
    id: str
    title: str
    keys: list[VlessKey]


@dataclass
class KeysData:
    groups: list[Group]
    total: int = 0  # сколько рабочих ключей всего
    # Когда закончилась проверка (time.time()); None — ключи не проверялись
    checked_at: float | None = field(default=None)

    def find(self, group_id: str) -> Group | None:
        return next((g for g in self.groups if g.id == group_id), None)

    def without(self, hidden: set[str]) -> "KeysData":
        groups = [replace(g, keys=[k for k in g.keys if k.url not in hidden]) for g in self.groups]
        return replace(self, groups=groups)

    @property
    def countries(self) -> list[Group]:
        return [g for g in self.groups if g.id != BEST_ID]


class KeysUnavailable(Exception):
    pass


def score(key: VlessKey) -> tuple:
    """Чем меньше, тем лучше. Сначала ключи с замеренной скоростью (скорость с поправкой на пинг),
    потом остальные — по пингу. Пинг из городов пользователей важнее пинга с сервера бота."""
    ping = key.user_ping if key.user_ping is not None else key.latency_ms
    if key.speed_mbps is not None:
        return 0, -key.speed_mbps * 100 / ((ping or 0) + 100)
    return 1, ping if ping is not None else 1e9


def build_data(ranked: list[VlessKey], per_group: int, max_countries: int, checked_at: float | None) -> KeysData:
    """ranked — ключи уже в порядке от лучшего к худшему."""
    for i, k in enumerate(ranked, 1):
        k.rank = i

    by_country: dict[str, list[VlessKey]] = defaultdict(list)
    for k in ranked:
        by_country[k.country].append(k)
    # Страны с большим числом ключей — выше; редкие собираем в «Другие страны»
    codes = sorted(by_country, key=lambda c: (-len(by_country[c]), by_country[c][0].rank))
    main, rest = codes[:max_countries], codes[max_countries:]

    groups = [Group(BEST_ID, "🏆 Лучшие", ranked[:per_group])]
    groups += [Group(f"cc.{c}", country_title(c), by_country[c][:per_group]) for c in main]
    if rest:
        other = sorted((k for c in rest for k in by_country[c]), key=lambda k: k.rank)
        groups.append(Group(OTHER_ID, "🌍 Другие страны", other[:per_group]))
    return KeysData(groups, total=len(ranked), checked_at=checked_at)


@dataclass
class CheckSettings:
    max_candidates: int = 400  # сколько ключей проверяем через Xray после проверки порта
    batch_size: int = 100  # ключей на один запуск Xray
    speed_top: int = 30  # у скольких лучших по пингу мерить скорость
    speed_bytes: int = 500_000  # размер файла для замера скорости
    user_ping_top: int = 50  # скольким лучшим ключам мерить пинг из Москвы и Беларуси
    min_verified: int = 10  # если проверенных из Москвы меньше — показываем и непроверенные
    per_group: int = 20  # ключей в одной стране
    max_countries: int = 14  # кнопок стран, остальные — в «Другие страны»


class KeysSource:
    def __init__(
        self,
        collector: Collector,
        checker: KeyChecker | None,
        globalping: Globalping | None,
        refresh_seconds: int,
        report_limit: int,
        settings: CheckSettings | None = None,
    ):
        self._collector = collector
        self._checker = checker
        self._globalping = globalping
        self._refresh_seconds = refresh_seconds
        self._report_limit = report_limit
        self._settings = settings or CheckSettings()
        self._data: KeysData | None = None
        self._first_ready = asyncio.Event()
        # Жалобы «не работает»: ключ -> id пользователей, которые пожаловались
        self._reports: dict[str, set[int]] = {}

    async def run(self) -> None:
        """Фоновый цикл: собрать ключи, проверить, подождать, повторить."""
        while True:
            ok = False
            try:
                await self._refresh()
                ok = True
            except Exception:
                log.exception("Не удалось обновить ключи")
            self._first_ready.set()
            await asyncio.sleep(self._refresh_seconds if ok else 60)

    async def get(self) -> KeysData:
        if self._data is None:
            # Сервер только проснулся и проверяет ключи. Долго не ждём: Telegram требует
            # ответить на нажатие кнопки за несколько секунд
            try:
                await asyncio.wait_for(self._first_ready.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
        if self._data is None:
            raise KeysUnavailable
        hidden = {url for url, users in self._reports.items() if len(users) >= self._report_limit}
        return self._data.without(hidden) if hidden else self._data

    def report(self, url: str, user_id: int) -> None:
        self._reports.setdefault(url, set()).add(user_id)
        log.info("Жалоба на ключ (%d): %s…", len(self._reports[url]), url[:60])

    def _publish(self, ranked: list[VlessKey]) -> None:
        s = self._settings
        self._data = build_data(ranked, s.per_group, s.max_countries, time.time())
        self._first_ready.set()

    @staticmethod
    def _good(probes: dict[str, Probe]) -> list[VlessKey]:
        keys = [
            VlessKey(url, p.latency_ms, country=p.country)
            for url, p in probes.items()
            if not p.failed and p.country not in EXCLUDED_EXITS
        ]
        return sorted(keys, key=score)

    async def _refresh(self) -> None:
        s = self._settings
        started = time.monotonic()
        urls = await self._collector.collect()

        if not self._checker:
            # Без Xray проверять нечем — показываем всё одной группой
            keys = [VlessKey(u, rank=i) for i, u in enumerate(urls[: s.per_group], 1)]
            self._data = KeysData([Group(BEST_ID, "🔑 Ключи", keys)], total=len(urls))
            return

        alive = (await self._checker.tcp_precheck(urls))[: s.max_candidates]
        log.info("Порт открыт у %d из %d (%.0f с)", len(alive), len(urls), time.monotonic() - started)

        first_run = self._data is None
        probes: dict[str, Probe] = {}
        for i in range(0, len(alive), s.batch_size):
            probes.update(await self._checker.probe(alive[i:i + s.batch_size]))
            if first_run and self._good(probes):
                # Сервер только проснулся — показываем первые результаты, не дожидаясь конца
                self._publish(self._good(probes))

        failed = Counter(name for p in probes.values() for name in p.failed)
        good = self._good(probes)
        log.info(
            "Работают как VPN: %d из %d; со всеми сервисами и выходом не в РФ: %d; не открылись: %s (%.0f с)",
            len(probes), len(alive), len(good), dict(failed) or "—", time.monotonic() - started,
        )
        if not good:
            log.warning("Ни один ключ не прошёл проверку — оставляю прошлый результат")
            return

        # Скорость — у самых быстрых по пингу
        speeds = await self._checker.probe_speed([k.url for k in good[: s.speed_top]], s.speed_bytes)
        for k in good:
            k.speed_mbps = speeds.get(k.url)
        good.sort(key=score)

        # Пинг из Москвы и Беларуси — у лучших. Примерно половина ключей, рабочих из-за границы,
        # в России заблокирована, поэтому показываем только тех, до кого достучалась Москва
        if self._globalping and s.user_ping_top:
            top = good[: s.user_ping_top]
            pings = await self._globalping.tcp_ping([entry_point(k.url) for k in top])
            verified, blocked = [], 0
            for k in top:
                k.user_pings = pings.get(entry_point(k.url), {})
                if k.user_pings.get(MAIN_LOCATION) is not None:
                    verified.append(k)
                elif MAIN_LOCATION in k.user_pings:
                    blocked += 1
            verified.sort(key=score)
            log.info("Пинг из СНГ замерен у %d, доступны из Москвы: %d, недоступны: %d",
                     len(pings), len(verified), blocked)
            if len(verified) >= s.min_verified:
                good = verified
            else:
                # Проверенных слишком мало (например, кончился лимит Globalping) — добавляем остальных
                log.warning("Проверенных из Москвы мало (%d) — показываю и непроверенные", len(verified))
                checked = {k.url for k in top if k.user_pings}
                good = verified + [k for k in good if k.url not in checked]

        self._publish(good)
        log.info(
            "Готово: %d ключей, скорость замерена у %d, всё заняло %.0f с",
            len(good), len(speeds), time.monotonic() - started,
        )
