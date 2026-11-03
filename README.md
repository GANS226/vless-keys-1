# vless-keys

Проверенные бесплатные VPN-ключи (VLESS, VMess, Trojan, Shadowsocks) и SOCKS5-прокси для
Telegram — для России и Беларуси. Данные для Telegram-бота [@vless_for_me_bot](https://t.me/vless_for_me_bot).

Каждые 30 минут GitHub Actions:
1. собирает ключи и прокси из открытых источников (`services/sources.py`) и из файлов
   `extra_keys.txt` / `extra_proxies.txt`;
2. проверяет каждый ключ через Xray: работает ли, страна выхода, открываются ли
   Telegram, Instagram, Discord и TikTok;
3. меряет скорость у самых быстрых и пинг до сервера из Москвы и Беларуси
   ([Globalping](https://globalping.io)); оставляет только ключи, доступные из Москвы;
4. проверяет прокси: соединяются ли с серверами Telegram, выход не из России, пинг из Москвы;
5. публикует результат в `https://<пользователь>.github.io/vless-keys/keys.json`.

Ключи и прокси берутся из публичных списков и могут перестать работать в любой момент.

Xray: https://github.com/XTLS/Xray-core (MPL-2.0).
