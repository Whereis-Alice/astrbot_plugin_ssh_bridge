from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncssh
from astrbot.api import logger

from .known_hosts import prepare_host_key
from .profiles import ProfileSet, ServerProfile
from .security import sanitize_text


class SSHBridgeError(RuntimeError):
    """User-safe plugin execution error."""


class CommandTimeoutError(SSHBridgeError):
    """A command exceeded the configured timeout."""


@dataclass(frozen=True)
class CommandResult:
    output: str
    exit_status: int | None
    truncated: bool = False


@dataclass
class HistoryRecord:
    command: str
    output: str
    time: datetime


@dataclass
class _ManagedSession:
    connection: asyncssh.SSHClientConnection
    process: asyncssh.SSHClientProcess | None
    profile_name: str
    last_active: datetime
    history: list[HistoryRecord]


class SSHSessionManager:
    def __init__(self, profiles: ProfileSet, config: Mapping[str, object], data_dir: Path):
        self.profiles = profiles
        self.data_dir = data_dir
        self.command_timeout = max(1, int(config.get("command_timeout", 30)))
        self.connect_timeout = max(1, int(config.get("connect_timeout", 10)))
        self.max_output_bytes = max(1024, int(config.get("max_output_bytes", 32768)))
        self.max_lines = max(1, int(config.get("max_lines", 80)))
        self.idle_timeout = max(1, int(config.get("idle_timeout", 30)))
        self.history_size = max(0, int(config.get("history_size", 50)))
        self.enable_history = bool(config.get("enable_history", True))
        self.sessions: dict[tuple[str, str], _ManagedSession] = {}
        self._lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._known_hosts_lock = asyncio.Lock()

    def _session_key(self, user_id: str, profile: ServerProfile) -> tuple[str, str]:
        return user_id, profile.name

    async def _load_private_key(self, profile: ServerProfile):
        key_data = profile.private_key
        if not key_data and profile.private_key_path:
            try:
                key_data = Path(profile.private_key_path).expanduser().read_text(
                    encoding="utf-8"
                )
            except OSError as exc:
                raise SSHBridgeError("无法读取 SSH 私钥文件。") from exc
        if not key_data:
            return None
        try:
            return [
                asyncssh.import_private_key(
                    key_data,
                    passphrase=profile.private_key_passphrase or None,
                )
            ]
        except Exception as exc:
            raise SSHBridgeError("SSH 私钥解析失败。") from exc

    async def _connect(self, profile: ServerProfile):
        client_keys = await self._load_private_key(profile)
        password = profile.password if client_keys is None else None
        try:
            return await asyncssh.connect(
                profile.host,
                port=profile.port,
                username=profile.username,
                password=password,
                client_keys=client_keys,
                known_hosts=str(profile.known_hosts_path),
                connect_timeout=self.connect_timeout,
                login_timeout=self.connect_timeout,
            )
        except Exception as exc:
            logger.error(
                "SSH Bridge: connection failed for profile %s: %s: %s",
                profile.name,
                type(exc).__name__,
                str(exc),
            )
            raise SSHBridgeError("SSH 连接失败。") from exc

    async def get_or_create(self, user_id: str, profile: ServerProfile):
        key = self._session_key(user_id, profile)
        async with self._lock:
            session = self.sessions.get(key)
            if session is not None:
                session.last_active = datetime.now(UTC)
                return session

        async with self._connect_lock:
            async with self._lock:
                session = self.sessions.get(key)
                if session is not None:
                    session.last_active = datetime.now(UTC)
                    return session

            await prepare_host_key(profile, self._known_hosts_lock)
            connection = await self._connect(profile)
            process = None
            try:
                if profile.resolved_execution_mode == "shell":
                    process = await connection.create_process(
                        "powershell.exe -NoLogo -NoProfile"
                        if profile.platform == "windows"
                        else None,
                        encoding=profile.encoding,
                        errors="replace",
                        stderr=asyncssh.STDOUT,
                    )
            except Exception:
                connection.close()
                raise
            managed = _ManagedSession(
                connection=connection,
                process=process,
                profile_name=profile.name,
                last_active=datetime.now(UTC),
                history=[],
            )
            async with self._lock:
                existing = self.sessions.get(key)
                if existing is not None:
                    existing.last_active = datetime.now(UTC)
                else:
                    self.sessions[key] = managed

            if existing is not None:
                await self._close_session(managed)
                return existing

            return managed

    @staticmethod
    async def _close_session(session: _ManagedSession) -> None:
        try:
            if session.process is not None:
                session.process.close()
                try:
                    await asyncio.wait_for(session.process.wait_closed(), timeout=3)
                except asyncio.TimeoutError:
                    pass
            session.connection.close()
            try:
                await asyncio.wait_for(session.connection.wait_closed(), timeout=3)
            except asyncio.TimeoutError:
                pass
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask the original result
            logger.warning("SSH Bridge: error while closing session: %s", type(exc).__name__)

    async def _drop_session(self, key: tuple[str, str], session: _ManagedSession) -> None:
        async with self._lock:
            if self.sessions.get(key) is session:
                self.sessions.pop(key, None)
        await self._close_session(session)

    async def _truncate(self, text: str) -> tuple[str, bool]:
        truncated = False
        encoded = text.encode("utf-8")
        if len(encoded) > self.max_output_bytes:
            encoded = encoded[-self.max_output_bytes :]
            text = encoded.decode("utf-8", errors="ignore")
            truncated = True
        lines = text.splitlines()
        if len(lines) > self.max_lines:
            text = "\n".join(lines[-self.max_lines :])
            truncated = True
        return text, truncated

    async def _execute_shell(
        self, session: _ManagedSession, profile: ServerProfile, command: str
    ) -> CommandResult:
        process = session.process
        if process is None or process.exit_status is not None:
            raise SSHBridgeError("远端 Shell 会话已退出。")

        marker = f"__SSH_BRIDGE_DONE_{uuid.uuid4().hex}__"
        if profile.platform == "windows":
            wrapped = f'{command}\nWrite-Output "{marker}:$(if ($?) {{ 0 }} else {{ 1 }})"\n'
        else:
            wrapped = f"{command}\nprintf '\\n{marker}:%s\\n' \"$?\"\n"
        process.stdin.write(wrapped)
        await process.stdin.drain()

        chunks: list[str] = []
        total_bytes = 0
        truncated = False
        timed_out = False
        exit_status: int | None = None
        deadline = asyncio.get_running_loop().time() + self.command_timeout

        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                timed_out = True
                break
            try:
                data = await asyncio.wait_for(
                    process.stdout.read(4096), timeout=min(0.5, remaining)
                )
            except asyncio.TimeoutError:
                if process.exit_status is not None:
                    break
                continue
            if data is None:
                break
            if data == "":
                if process.exit_status is not None:
                    break
                continue

            chunk = str(data)
            chunks.append(chunk)
            total_bytes += len(chunk.encode(profile.encoding, errors="ignore"))
            joined = "".join(chunks)
            match = re.search(rf"\n?{marker}:(\d+)\s*$", joined, re.MULTILINE)
            if match:
                exit_status = int(match.group(1))
                joined = joined[: match.start()].rstrip("\r\n")
                chunks = [joined]
                break
            if total_bytes >= self.max_output_bytes:
                truncated = True
                break

        output = "".join(chunks)
        output = output.replace("\r\n", "\n").replace("\r", "\n")
        output, size_truncated = await self._truncate(output)
        truncated = truncated or size_truncated
        if exit_status is None and process.exit_status is not None:
            exit_status = process.exit_status
        if timed_out:
            raise CommandTimeoutError(
                f"命令超过 {self.command_timeout} 秒未结束，会话已关闭。"
            )
        return CommandResult(output=output, exit_status=exit_status, truncated=truncated)

    async def _execute_run(
        self, session: _ManagedSession, profile: ServerProfile, command: str
    ) -> CommandResult:
        try:
            completed = await session.connection.run(
                command,
                timeout=self.command_timeout,
                check=False,
                encoding=profile.encoding,
                errors="replace",
            )
        except asyncio.TimeoutError as exc:
            raise CommandTimeoutError(
                f"命令超过 {self.command_timeout} 秒未结束，会话已关闭。"
            ) from exc

        output_parts = []
        if completed.stdout:
            output_parts.append(str(completed.stdout))
        if completed.stderr:
            output_parts.append("[stderr]\n" + str(completed.stderr))
        output = "\n".join(output_parts)
        output = output.replace("\r\n", "\n").replace("\r", "\n")
        output, truncated = await self._truncate(output)
        return CommandResult(
            output=output,
            exit_status=completed.exit_status,
            truncated=truncated,
        )

    async def execute(self, user_id: str, profile: ServerProfile, command: str):
        key = self._session_key(user_id, profile)
        session = await self.get_or_create(user_id, profile)
        try:
            if profile.resolved_execution_mode == "shell":
                result = await self._execute_shell(session, profile, command)
            else:
                result = await self._execute_run(session, profile, command)
        except CommandTimeoutError:
            await self._drop_session(key, session)
            raise
        except (SSHBridgeError, asyncssh.Error, OSError, EOFError):
            await self._drop_session(key, session)
            raise

        if self.enable_history and self.history_size > 0:
            session.history.append(
                HistoryRecord(
                    command=sanitize_text(command),
                    output=sanitize_text(result.output),
                    time=datetime.now(UTC),
                )
            )
            del session.history[:-self.history_size]
        session.last_active = datetime.now(UTC)
        return result

    async def diagnose(self, user_id: str, profile: ServerProfile) -> CommandResult:
        session = await self.get_or_create(user_id, profile)
        outputs = []
        for command in ("whoami", "hostname"):
            completed = await session.connection.run(
                command,
                timeout=10,
                check=False,
                encoding=profile.encoding,
                errors="replace",
            )
            if completed.stdout:
                outputs.append(f"{command}: {str(completed.stdout).strip()}")
        return CommandResult(output="\n".join(outputs), exit_status=0)

    def get_history(self, user_id: str, profile: ServerProfile, limit: int) -> list[HistoryRecord]:
        session = self.sessions.get(self._session_key(user_id, profile))
        if session is None:
            return []
        return session.history[-max(1, limit) :]

    def has_session(self, user_id: str, profile: ServerProfile) -> bool:
        return self._session_key(user_id, profile) in self.sessions

    async def close_user(self, user_id: str, profile: ServerProfile | None = None) -> bool:
        keys = [
            key
            for key in self.sessions
            if key[0] == user_id and (profile is None or key[1] == profile.name)
        ]
        sessions: list[_ManagedSession] = []
        async with self._lock:
            for key in keys:
                session = self.sessions.pop(key, None)
                if session is not None:
                    sessions.append(session)
        for session in sessions:
            await self._close_session(session)
        return bool(sessions)

    async def cleanup_expired(self) -> None:
        now = datetime.now(UTC)
        expired = [
            (key, session)
            for key, session in self.sessions.items()
            if now - session.last_active > timedelta(minutes=self.idle_timeout)
        ]
        for key, session in expired:
            await self._drop_session(key, session)
            logger.info(
                "SSH Bridge: closed idle session for %s on profile %s", key[0], key[1]
            )

    async def close_all(self) -> None:
        async with self._lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            await self._close_session(session)
