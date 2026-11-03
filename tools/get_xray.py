"""Скачивает Xray в папку bin/ — он нужен боту, чтобы проверять ключи.

Render запускает это при сборке (см. render.yaml). Локально: python tools/get_xray.py
"""
import io
import os
import platform
import stat
import time
import urllib.request
import zipfile
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"


def main() -> None:
    if os.name == "nt":
        archive, exe = "Xray-windows-64.zip", "xray.exe"
    elif platform.machine().lower() in ("aarch64", "arm64"):
        archive, exe = "Xray-linux-arm64-v8a.zip", "xray"
    else:
        archive, exe = "Xray-linux-64.zip", "xray"

    url = f"https://github.com/XTLS/Xray-core/releases/latest/download/{archive}"
    for attempt in range(1, 4):
        print(f"Скачиваю {url} (попытка {attempt})")
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                data = resp.read()
            break
        except OSError as e:
            print(f"Ошибка: {e}")
            if attempt == 3:
                raise
            time.sleep(5)

    BIN.mkdir(exist_ok=True)
    target = BIN / exe
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        target.write_bytes(zf.read(exe))
    target.chmod(target.stat().st_mode | stat.S_IEXEC)
    print(f"Готово: {target}")


if __name__ == "__main__":
    main()
