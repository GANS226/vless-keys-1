"""Разбор ссылок vless:// vmess:// trojan:// ss:// в outbound для Xray и смена подписи ключа."""
import base64
import ipaddress
import json
import re
from urllib.parse import quote, unquote

PROTOCOLS = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "ss": "Shadowsocks"}
LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>\\`]+")
_HOSTPORT_RE = re.compile(r"^(\[[^\]]+\]|[^:/?#\[\]]+):(\d{1,5})$")

# Шифры Shadowsocks, которые понимает Xray
SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
VMESS_SECURITY = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}


def protocol_of(url: str) -> str:
    return url.split("://", 1)[0].lower()


def _b64decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")


def _is_private(address: str) -> bool:
    if address == "localhost":
        return True
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def _parse_query(query: str) -> dict[str, str]:
    params = {}
    for pair in query.lstrip("?").split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        # Не используем parse_qsl: он превращает «+» в пробел, а в path он бывает настоящим
        params[key.lower()] = unquote(value)
    return params


def _host_port(text: str) -> tuple[str, int]:
    m = _HOSTPORT_RE.match(text.rstrip("/"))
    if not m or not 0 < int(m[2]) < 65536:
        raise ValueError("нет адреса или порта")
    return m[1].strip("[]"), int(m[2])


def _split(url: str) -> tuple[str, str, int, dict[str, str]]:
    """userinfo, хост, порт, параметры — для ссылок вида схема://userinfo@хост:порт?параметры#имя"""
    body = url.split("://", 1)[1].split("#", 1)[0]
    body, _, query = body.partition("?")
    userinfo, at, hostport = body.rpartition("@")
    if not at:
        raise ValueError("нет @ в ссылке")
    host, port = _host_port(hostport)
    return unquote(userinfo), host, port, _parse_query(query)


def _stream(q: dict[str, str], address: str, default_security: str = "none") -> dict:
    """streamSettings Xray по параметрам ссылки (общие для VLESS, Trojan и VMess)."""
    # В чужих списках бывает мусор вроде «tcp#🎡90@канал» — берём только буквы в начале
    network = re.match(r"[a-z0-9-]*", (q.get("type") or "tcp").lower()).group() or "tcp"
    network = {"splithttp": "xhttp", "raw": "tcp", "none": "tcp"}.get(network, network)
    security = (q.get("security") or default_security).lower()
    if security in ("", "false", "0"):
        security = "none"
    host = q.get("host") or ""
    path = q.get("path") or "/"
    sni = q.get("sni") or q.get("peer") or host.split(",")[0] or address
    fingerprint = q.get("fp") or "chrome"

    stream: dict = {"network": network, "security": security}
    if security == "tls":
        tls = {"serverName": sni, "fingerprint": fingerprint}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        # allowInsecure не переносим: новый Xray его убрал и не запускается с ним
        stream["tlsSettings"] = tls
    elif security == "reality":
        if not q.get("pbk"):
            raise ValueError("reality без pbk")
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "publicKey": q["pbk"],
            "shortId": q.get("sid") or "",
            "spiderX": q.get("spx") or "",
        }
    elif security != "none":
        raise ValueError(f"неизвестный security={security}")

    if network == "ws":
        stream["wsSettings"] = {"path": path, "host": host}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, "host": host}
    elif network == "xhttp":
        xhttp = {"path": path, "host": host, "mode": q.get("mode") or "auto"}
        if q.get("extra"):
            xhttp["extra"] = json.loads(q["extra"])
        stream["xhttpSettings"] = xhttp
    elif network == "grpc":
        grpc = {"serviceName": q.get("servicename") or "", "multiMode": q.get("mode") == "multi"}
        if q.get("authority"):
            grpc["authority"] = q["authority"]
        stream["grpcSettings"] = grpc
    elif network == "tcp":
        if q.get("headertype") == "http":
            stream["tcpSettings"] = {"header": {
                "type": "http",
                "request": {"path": [path], "headers": {"Host": [host]}},
            }}
    else:
        raise ValueError(f"неподдерживаемый type={network}")
    return stream


def _vless(url: str) -> dict:
    user_id, address, port, q = _split(url)
    encryption = q.get("encryption") or "none"
    if encryption.lower().startswith("none"):
        # В чужих списках встречается мусор вроде «none@канал» — Xray с таким не запускается
        encryption = "none"
    user = {"id": user_id, "encryption": encryption}
    if q.get("flow"):
        user["flow"] = q["flow"]
    stream = _stream(q, address)
    if stream["security"] == "none" and not _is_private(address):
        # Новый Xray запрещает VLESS без шифрования к публичным серверам (и такие ключи легко блокируются)
        raise ValueError("vless без шифрования")
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]},
        "streamSettings": stream,
    }


def _trojan(url: str) -> dict:
    password, address, port, q = _split(url)
    stream = _stream(q, address, default_security="tls")
    if stream["security"] == "none" and not _is_private(address):
        raise ValueError("trojan без шифрования")
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": address, "port": port, "password": password}]},
        "streamSettings": stream,
    }


def _vmess(url: str) -> dict:
    d = json.loads(_b64decode(url[len("vmess://"):].split("#", 1)[0]))
    address = str(d.get("add") or "")
    port = int(str(d.get("port") or 0))
    if not address or not 0 < port < 65536:
        raise ValueError("нет адреса или порта")
    network = str(d.get("net") or "tcp")
    q = {
        "type": network,
        "security": "tls" if str(d.get("tls") or "").lower() == "tls" else "none",
        "host": str(d.get("host") or ""),
        "path": str(d.get("path") or ""),
        "sni": str(d.get("sni") or ""),
        "alpn": str(d.get("alpn") or ""),
        "fp": str(d.get("fp") or ""),
        "headertype": str(d.get("type") or ""),
        "servicename": str(d.get("path") or "") if network == "grpc" else "",
        "mode": str(d.get("type") or "") if network == "grpc" else "",
    }
    security = str(d.get("scy") or "auto").lower()
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{
            "address": address,
            "port": port,
            "users": [{"id": str(d["id"]), "security": security if security in VMESS_SECURITY else "auto"}],
        }]},
        "streamSettings": _stream(q, address),
    }


def _shadowsocks(url: str) -> dict:
    body = url[len("ss://"):].split("#", 1)[0]
    body, _, query = body.partition("?")
    if "plugin=" in query:
        raise ValueError("ss с плагином")
    body = body.rstrip("/")
    if "@" in body:
        # ss://base64(метод:пароль)@хост:порт или ss://метод:пароль@хост:порт
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = unquote(userinfo)
        if ":" not in userinfo:
            userinfo = _b64decode(userinfo)
    else:
        # ss://base64(метод:пароль@хост:порт)
        userinfo, hostport = _b64decode(body).rsplit("@", 1)
    method, _, password = userinfo.partition(":")
    method = method.lower()
    if method not in SS_METHODS:
        raise ValueError(f"шифр {method} не поддерживается")
    address, port = _host_port(hostport)
    return {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": address, "port": port, "method": method, "password": password}]},
    }


_PARSERS = {"vless": _vless, "trojan": _trojan, "vmess": _vmess, "ss": _shadowsocks}


def link_to_outbound(url: str, tag: str) -> dict:
    parser = _PARSERS.get(protocol_of(url))
    if not parser:
        raise ValueError("неподдерживаемый протокол")
    try:
        outbound = parser(url.strip())
    except (KeyError, TypeError, IndexError) as e:
        raise ValueError(f"битая ссылка: {e}") from e
    return {"tag": tag, **outbound}


def entry_point(url: str) -> tuple[str, int]:
    """Адрес сервера, к которому подключается пользователь."""
    settings = link_to_outbound(url, "x")["settings"]
    server = (settings.get("vnext") or settings.get("servers"))[0]
    return server["address"], server["port"]


def with_label(url: str, label: str) -> str:
    """Ключ с другой подписью (её видно в приложении). У VMess подпись внутри base64."""
    if protocol_of(url) == "vmess":
        d = json.loads(_b64decode(url[len("vmess://"):].split("#", 1)[0]))
        d["ps"] = label
        return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()
    return f"{url.split('#', 1)[0]}#{quote(label)}"
