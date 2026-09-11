from __future__ import annotations

import asyncio
from pathlib import Path

import asyncssh
from astrbot.api import logger

from .profiles import ServerProfile


def _host_entry(host: str, port: int) -> str:
    if port == 22:
        return f"[{host}]" if ":" in host else host
    return f"[{host}]:{port}"


def _ensure_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def _host_in_known_hosts(path: Path, host: str, port: int) -> bool:
    entry = _host_entry(host, port)
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            fields = line.split(maxsplit=2)
            if fields and fields[0].lstrip("@").lower() == entry.lower():
                return True
    except FileNotFoundError:
        return False
    return False


async def prepare_host_key(profile: ServerProfile, lock: asyncio.Lock) -> None:
    """Trust-on-first-use host key capture, serialized across profiles."""
    path = profile.known_hosts_path
    _ensure_file(path)
    if _host_in_known_hosts(path, profile.host, profile.port):
        return
    if profile.host_key_policy == "strict":
        return

    async with lock:
        _ensure_file(path)
        if _host_in_known_hosts(path, profile.host, profile.port):
            return

        try:
            server_key = await asyncio.wait_for(
                asyncssh.get_server_host_key(profile.host, profile.port),
                timeout=10,
            )
        except Exception as exc:  # noqa: BLE001 - host key scan failures are advisory only
            logger.warning(
                "SSH Bridge: host key scan failed for %s:%s: %s",
                profile.host,
                profile.port,
                type(exc).__name__,
            )
            return

        if server_key is None:
            logger.warning(
                "SSH Bridge: host key scan returned no key for %s:%s",
                profile.host,
                profile.port,
            )
            return

        key_data = server_key.export_public_key("openssh")
        if isinstance(key_data, bytes):
            key_data = key_data.decode("ascii", errors="ignore").strip()
        with path.open("a", encoding="ascii", newline="\n") as file:
            file.write(f"{_host_entry(profile.host, profile.port)} {key_data.strip()}\n")
        logger.info(
            "SSH Bridge: saved host key for %s:%s to %s",
            profile.host,
            profile.port,
            path,
        )
