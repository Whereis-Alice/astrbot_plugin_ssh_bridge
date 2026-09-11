from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, StarTools

from .ssh_bridge import PLUGIN_NAME
from .ssh_bridge.executor import CommandResult, SSHBridgeError, SSHSessionManager
from .ssh_bridge.profiles import ProfileError, ProfileSet, ServerProfile, load_profiles
from .ssh_bridge.security import CheckResult, check_command, sanitize_text


class SSHBridgePlugin(Star):
    """通过 SSH 管理多台 Linux 或 Windows 服务器。"""

    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.profile_set: ProfileSet | None = None
        self.manager: SSHSessionManager | None = None
        self.config_error: str | None = None
        self.active_profiles: dict[str, str] = {}
        self.pending_confirms: dict[str, dict[str, object]] = {}

        try:
            data_dir = StarTools.get_data_dir(PLUGIN_NAME)
            self.profile_set = load_profiles(config, data_dir)
            self.manager = SSHSessionManager(self.profile_set, config, data_dir)
        except Exception as exc:  # noqa: BLE001 - configuration parsing must stay non-fatal
            self.config_error = str(exc)
            logger.error("SSH Bridge: invalid configuration: %s", exc)

        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def terminate(self):
        """Cancel background cleanup and close all SSH connections."""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        if self.manager:
            await self.manager.close_all()

    async def _cleanup_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(60)
                if self.manager:
                    await self.manager.cleanup_expired()
                timeout = max(5, int(self.config.get("confirm_timeout", 60)))
                now = asyncio.get_running_loop().time()
                expired = [
                    user_id
                    for user_id, pending in self.pending_confirms.items()
                    if now - float(pending["created_at"]) > timeout
                ]
                for user_id in expired:
                    self.pending_confirms.pop(user_id, None)
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001 - cleanup must never kill the plugin loop
                logger.error("SSH Bridge: cleanup failed: %s", type(exc).__name__)

    @staticmethod
    def _extract_command(event: AstrMessageEvent) -> str:
        raw = event.message_str.strip()
        match = re.match(r"^(?:/ssh|ssh)(?=\s|$)", raw, flags=re.IGNORECASE)
        if match:
            raw = raw[match.end() :]
        return raw.strip()

    @staticmethod
    def _help_text() -> str:
        return (
            "SSH Bridge 用法:\n"
            "/ssh <命令> 在当前服务器执行命令\n"
            "/ssh use <名称> 切换服务器\n"
            "/ssh servers 查看服务器档案\n"
            "/ssh status 查看当前状态\n"
            "/ssh doctor 检查当前服务器连接\n"
            "/ssh log [条数] 查看最近执行记录\n"
            "/ssh out 断开当前服务器会话\n"
            "/ssh yes / /ssh no 确认或取消待确认命令"
        )

    def _resolve_profile(self, user_id: str, requested: str = "") -> ServerProfile:
        if self.profile_set is None:
            raise ProfileError(self.config_error or "服务器配置未加载。")
        if requested.strip():
            return self.profile_set.get(requested)
        active_name = self.active_profiles.get(user_id)
        if active_name:
            return self.profile_set.get(active_name)
        return self.profile_set.get(self.profile_set.default_server)

    def _check_command(self, command: str, profile: ServerProfile) -> CheckResult:
        max_length = max(1, int(self.config.get("max_command_length", 4096)))
        if len(command) > max_length:
            return CheckResult.BLOCK
        return check_command(
            command,
            profile.platform,
            profile.command_whitelist,
            allow_all=bool(self.config.get("enable_dangerous_commands", False)),
        )

    @staticmethod
    def _format_result(result: CommandResult) -> str:
        output = sanitize_text(result.output.strip() or "(无输出)")
        parts: list[str] = []
        if result.exit_status not in (None, 0):
            parts.append(f"exit code: {result.exit_status}")
        parts.append(output)
        if result.truncated:
            parts.append("输出已按配置截断。")
        return "\n".join(parts)

    async def _send_output(self, event: AstrMessageEvent, result: CommandResult):
        text = self._format_result(result)
        mode = str(self.config.get("output_mode", "auto")).lower()
        should_render = mode == "auto" and (len(text) > 1200 or len(text.splitlines()) > 20)
        if should_render:
            try:
                image = await self.text_to_image(text)
                yield event.image_result(image)
                return
            except Exception as exc:  # noqa: BLE001 - rendering is an optional output path
                logger.warning("SSH Bridge: output image render failed: %s", type(exc).__name__)
        if len(text) > 6000:
            text = text[-6000:]
        yield event.plain_result(text)

    async def _handle_servers(self, event: AstrMessageEvent):
        if self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        user_id = event.get_sender_id()
        active_name = self.active_profiles.get(user_id, self.profile_set.default_server)
        lines = ["服务器档案:"]
        for profile in self.profile_set.servers:
            marker = " (当前)" if profile.name == active_name else ""
            default = " [默认]" if profile.name == self.profile_set.default_server else ""
            lines.append(
                f"- {profile.name}{default}{marker}: {profile.username}@"
                f"{profile.host}:{profile.port}, {profile.platform}, "
                f"{profile.resolved_execution_mode} 模式"
            )
        yield event.plain_result("\n".join(lines))

    async def _handle_use(self, event: AstrMessageEvent, name: str):
        if self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        try:
            profile = self.profile_set.get(name)
        except ProfileError as exc:
            yield event.plain_result(str(exc))
            return

        user_id = event.get_sender_id()
        old_name = self.active_profiles.get(user_id)
        if self.manager and old_name:
            try:
                await self.manager.close_user(user_id, self.profile_set.get(old_name))
            except ProfileError:
                pass
        self.active_profiles[user_id] = profile.name
        yield event.plain_result(f"已切换到 {profile.summary()}。旧会话已断开。")

    async def _handle_status(self, event: AstrMessageEvent):
        if self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        user_id = event.get_sender_id()
        profile = self._resolve_profile(user_id)
        connected = bool(self.manager and self.manager.has_session(user_id, profile))
        state = "已连接" if connected else "未连接"
        yield event.plain_result(
            f"当前服务器: {profile.summary()}\n"
            f"执行模式: {profile.resolved_execution_mode}\n"
            f"会话状态: {state}\n"
            f"默认服务器: {self.profile_set.default_server}"
        )

    async def _handle_doctor(self, event: AstrMessageEvent, server: str):
        if self.manager is None or self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        user_id = event.get_sender_id()
        try:
            profile = self._resolve_profile(user_id, server)
            result = await self.manager.diagnose(user_id, profile)
        except Exception as exc:  # noqa: BLE001 - diagnostics report unexpected transport failures
            logger.error("SSH Bridge: doctor failed: %s: %s", type(exc).__name__, exc)
            yield event.plain_result("连接诊断失败，请查看 AstrBot 日志。")
            return
        async for message in self._send_output(event, result):
            yield message

    async def _handle_log(self, event: AstrMessageEvent, argument: str):
        if self.manager is None or self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        if not bool(self.config.get("enable_history", True)):
            yield event.plain_result("历史记录已关闭。")
            return

        user_id = event.get_sender_id()
        profile = self._resolve_profile(user_id)
        limit = max(1, int(self.config.get("log_size", 5)))
        if argument.strip().isdigit():
            limit = min(50, max(1, int(argument.strip())))
        records = self.manager.get_history(user_id, profile, limit)
        if not records:
            yield event.plain_result("暂无执行记录。")
            return

        lines = [f"最近 {len(records)} 条执行记录:"]
        for record in records:
            time_text = record.time.strftime("%m-%d %H:%M:%S")
            preview = record.output.replace("\n", " ")
            if len(preview) > 80:
                preview = preview[:80] + "..."
            lines.append(f"[{time_text}] {record.command}\n  {preview}")
        yield event.plain_result("\n".join(lines))

    async def _handle_out(self, event: AstrMessageEvent):
        if self.manager is None or self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        user_id = event.get_sender_id()
        profile = self._resolve_profile(user_id)
        closed = await self.manager.close_user(user_id, profile)
        if closed:
            yield event.plain_result(f"已断开 {profile.name} 的 SSH 会话。")
        else:
            yield event.plain_result(f"{profile.name} 当前没有活跃会话。")

    async def _handle_confirm(self, event: AstrMessageEvent, confirmed: bool):
        if self.profile_set is None or self.manager is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        user_id = event.get_sender_id()
        pending = self.pending_confirms.pop(user_id, None)
        if pending is None:
            yield event.plain_result("当前没有待确认命令。")
            return
        if not confirmed:
            yield event.plain_result("已取消执行。")
            return

        timeout = max(5, int(self.config.get("confirm_timeout", 60)))
        if asyncio.get_running_loop().time() - float(pending["created_at"]) > timeout:
            yield event.plain_result("确认已超时，请重新发送命令。")
            return

        command = str(pending["command"])
        profile_name = str(pending["profile"])
        try:
            profile = self.profile_set.get(profile_name)
        except ProfileError:
            yield event.plain_result("待确认命令的服务器档案已失效，请重新执行。")
            return
        async for message in self._do_execute(event, user_id, profile, command):
            yield message

    async def _do_execute(
        self,
        event: AstrMessageEvent,
        user_id: str,
        profile: ServerProfile,
        command: str,
    ) -> AsyncIterator[object]:
        if self.manager is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return

        yield event.plain_result(f"正在 {profile.name} 上执行...")
        try:
            result = await self.manager.execute(user_id, profile, command)
        except SSHBridgeError as exc:
            yield event.plain_result(str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - user-facing command boundary
            logger.error(
                "SSH Bridge: command execution failed: %s: %s",
                type(exc).__name__,
                exc,
            )
            yield event.plain_result("命令执行失败，请查看 AstrBot 日志。")
            return

        async for message in self._send_output(event, result):
            yield message

    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("ssh")
    async def ssh_cmd(self, event: AstrMessageEvent):
        """执行远程 SSH 命令，并管理服务器会话。"""
        user_id = event.get_sender_id()
        command = self._extract_command(event)
        if not command:
            yield event.plain_result(self._help_text())
            return

        parts = command.split(maxsplit=1)
        sub_command = parts[0].lower()
        argument = parts[1].strip() if len(parts) > 1 else ""

        if sub_command in {"help", "?"}:
            yield event.plain_result(self._help_text())
            return
        if sub_command == "servers":
            async for message in self._handle_servers(event):
                yield message
            return
        if sub_command == "use":
            if not argument:
                yield event.plain_result("用法: /ssh use <服务器名称>")
                return
            async for message in self._handle_use(event, argument):
                yield message
            return
        if sub_command == "status":
            async for message in self._handle_status(event):
                yield message
            return
        if sub_command == "doctor":
            async for message in self._handle_doctor(event, argument):
                yield message
            return
        if sub_command == "log":
            async for message in self._handle_log(event, argument):
                yield message
            return
        if sub_command in {"out", "disconnect"}:
            async for message in self._handle_out(event):
                yield message
            return
        if sub_command in {"yes", "no"}:
            async for message in self._handle_confirm(event, sub_command == "yes"):
                yield message
            return

        if self.profile_set is None:
            yield event.plain_result(self.config_error or "服务器配置未加载。")
            return
        try:
            profile = self._resolve_profile(user_id)
        except ProfileError as exc:
            yield event.plain_result(str(exc))
            return

        check = self._check_command(command, profile)
        if check == CheckResult.BLOCK:
            yield event.plain_result(
                f"命令已被安全策略阻止:\n{sanitize_text(command)}"
            )
            return
        if check == CheckResult.CONFIRM:
            timeout = max(5, int(self.config.get("confirm_timeout", 60)))
            self.pending_confirms[user_id] = {
                "command": command,
                "profile": profile.name,
                "created_at": asyncio.get_running_loop().time(),
            }
            yield event.plain_result(
                f"命令不在白名单中，需要确认:\n{sanitize_text(command)}\n"
                f"目标服务器: {profile.name}\n"
                f"{timeout} 秒内发送 /ssh yes 执行，/ssh no 取消。"
            )
            return

        async for message in self._do_execute(event, user_id, profile, command):
            yield message

    @filter.llm_tool(name="ssh_bridge_exec")
    async def ssh_bridge_exec(
        self,
        event: AstrMessageEvent,
        command: str,
        server: str = "",
    ) -> str:
        """Execute an allowed SSH command on a configured server.

        Args:
            command (string): The shell or PowerShell command to execute.
            server (string): Optional server profile name. Defaults to the current server.
        """
        if not event.is_admin():
            return "该工具仅 AstrBot 管理员可用。"
        if self.profile_set is None or self.manager is None:
            return self.config_error or "服务器配置未加载。"

        user_id = event.get_sender_id()
        try:
            profile = self._resolve_profile(user_id, server)
        except ProfileError as exc:
            return str(exc)

        check = self._check_command(command, profile)
        if check == CheckResult.BLOCK:
            return "命令已被安全策略阻止。"
        if check == CheckResult.CONFIRM:
            return (
                "该命令不在白名单中，LLM 不能自动执行。"
                "请管理员使用 /ssh 手动执行并确认。"
            )

        try:
            result = await self.manager.execute(user_id, profile, command)
        except SSHBridgeError as exc:
            return str(exc)
        except Exception:  # noqa: BLE001 - tool result must always be valid for the LLM
            logger.exception("SSH Bridge: LLM tool execution failed")
            return "命令执行失败，请查看 AstrBot 日志。"

        text = self._format_result(result)
        return text[-4000:]
