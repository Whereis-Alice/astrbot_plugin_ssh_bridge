from __future__ import annotations

import codecs
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProfileError(ValueError):
    """Raised when the server profile configuration is unusable."""


_VALID_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class ServerProfile:
    name: str
    host: str
    port: int
    username: str
    password: str
    private_key: str
    private_key_path: str
    private_key_passphrase: str
    platform: str
    execution_mode: str
    host_key_policy: str
    encoding: str
    known_hosts_path: Path
    command_whitelist: tuple[str, ...]

    @property
    def resolved_execution_mode(self) -> str:
        if self.execution_mode == "run":
            return "run"
        if self.execution_mode == "shell":
            return "shell"
        return "run" if self.platform == "windows" else "shell"

    def summary(self) -> str:
        return f"{self.name} ({self.username}@{self.host}:{self.port}, {self.platform})"


@dataclass(frozen=True)
class ProfileSet:
    servers: tuple[ServerProfile, ...]
    default_server: str

    def get(self, name: str) -> ServerProfile:
        normalized = name.strip()
        for server in self.servers:
            if server.name == normalized:
                return server
        raise ProfileError(f"服务器档案 {normalized!r} 不存在。")


def _int_value(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"{field} 必须是整数。") from exc


def _string_value(value: Any, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ProfileError(f"{field} 必须是字符串。")
    return value.strip()


def _resolve_path(value: str, fallback: Path, field: str) -> Path:
    if not value:
        return fallback
    try:
        expanded = os.path.expandvars(os.path.expanduser(value))
        return Path(expanded).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ProfileError(f"无法解析 {field}: {value}") from exc


def load_profiles(config: Mapping[str, Any], data_dir: Path) -> ProfileSet:
    """Validate server profiles and return a deterministic profile set."""
    raw_servers = config.get("servers") or []
    if not isinstance(raw_servers, list):
        raise ProfileError("servers 必须是服务器档案列表。")

    global_known_hosts = _resolve_path(
        _string_value(config.get("known_hosts_path", ""), "known_hosts_path"),
        data_dir / "known_hosts",
        "known_hosts_path",
    )
    global_whitelist = tuple(
        item.strip()
        for item in (config.get("command_whitelist") or [])
        if isinstance(item, str) and item.strip()
    )

    profiles: list[ServerProfile] = []
    errors: list[str] = []
    names: set[str] = set()

    for index, raw in enumerate(raw_servers):
        if not isinstance(raw, Mapping):
            errors.append(f"servers[{index}] 必须是对象。")
            continue
        if not bool(raw.get("enabled", True)):
            continue

        label = f"servers[{index}]"
        name = _string_value(raw.get("name", ""), f"{label}.name")
        if not name:
            errors.append(f"{label}.name 不能为空。")
            continue
        if not _VALID_NAME.fullmatch(name):
            errors.append(f"{label}.name 只能包含字母、数字、点、下划线、中划线。")
            continue
        if name in names:
            errors.append(f"服务器名称重复: {name}")
            continue

        host = _string_value(raw.get("host", ""), f"{label}.host")
        username = _string_value(raw.get("username", ""), f"{label}.username")
        password = _string_value(raw.get("password", ""), f"{label}.password")
        private_key = _string_value(raw.get("private_key", ""), f"{label}.private_key")
        private_key_path = _string_value(
            raw.get("private_key_path", ""), f"{label}.private_key_path"
        )
        private_key_passphrase = _string_value(
            raw.get("private_key_passphrase", ""), f"{label}.private_key_passphrase"
        )

        if not host:
            errors.append(f"{label}.host 不能为空。")
        if not username:
            errors.append(f"{label}.username 不能为空。")
        if not password and not private_key and not private_key_path:
            errors.append(f"{label}: password、private_key、private_key_path 至少填写一项。")
        if any((not host, not username, not password and not private_key and not private_key_path)):
            continue

        port = _int_value(raw.get("port", 22), f"{label}.port")
        if not 1 <= port <= 65535:
            errors.append(f"{label}.port 必须在 1-65535 之间。")
            continue

        platform = _string_value(raw.get("platform", "linux"), f"{label}.platform").lower()
        if platform not in {"linux", "windows"}:
            errors.append(f"{label}.platform 只支持 linux 或 windows。")
            continue

        execution_mode = _string_value(
            raw.get("execution_mode", "auto"), f"{label}.execution_mode"
        ).lower()
        if execution_mode not in {"auto", "shell", "run"}:
            errors.append(f"{label}.execution_mode 只支持 auto、shell 或 run。")
            continue

        host_key_policy = _string_value(
            raw.get("host_key_policy", "tofu"), f"{label}.host_key_policy"
        ).lower()
        if host_key_policy not in {"tofu", "strict"}:
            errors.append(f"{label}.host_key_policy 只支持 tofu 或 strict。")
            continue

        encoding = _string_value(raw.get("encoding", "utf-8"), f"{label}.encoding").lower()
        try:
            codecs.lookup(encoding)
        except LookupError:
            errors.append(f"{label}.encoding 不是有效的 Python 编码。")
            continue

        raw_whitelist = raw.get("command_whitelist") or []
        if not isinstance(raw_whitelist, list):
            errors.append(f"{label}.command_whitelist 必须是列表。")
            continue
        whitelist = tuple(
            item.strip() for item in raw_whitelist if isinstance(item, str) and item.strip()
        ) or global_whitelist

        names.add(name)
        profiles.append(
            ServerProfile(
                name=name,
                host=host,
                port=port,
                username=username,
                password=password,
                private_key=private_key,
                private_key_path=private_key_path,
                private_key_passphrase=private_key_passphrase,
                platform=platform,
                execution_mode=execution_mode,
                host_key_policy=host_key_policy,
                encoding=encoding,
                known_hosts_path=_resolve_path(
                    _string_value(raw.get("known_hosts_path", ""), f"{label}.known_hosts_path"),
                    global_known_hosts,
                    f"{label}.known_hosts_path",
                ),
                command_whitelist=whitelist,
            )
        )

    if not profiles:
        if errors:
            raise ProfileError("\n".join(errors))
        raise ProfileError("请先在插件配置中添加至少一台启用的服务器。")

    default_name = _string_value(config.get("default_server", ""), "default_server")
    if default_name:
        if default_name not in names:
            raise ProfileError(f"default_server {default_name!r} 不存在。")
    else:
        default_name = profiles[0].name

    if errors:
        raise ProfileError("\n".join(errors))
    return ProfileSet(servers=tuple(profiles), default_server=default_name)
