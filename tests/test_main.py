from __future__ import annotations

import asyncio
import unittest

from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.permission import PermissionTypeFilter
from astrbot.core.star.star_handler import star_handlers_registry

from main import SSHBridgePlugin


class _Event:
    def __init__(self, message: str):
        self.message_str = message


class ExtractCommandTests(unittest.TestCase):
    def test_extracts_full_command_after_prefix(self):
        self.assertEqual(
            SSHBridgePlugin._extract_command(_Event("/ssh df -h")),
            "df -h",
        )
        self.assertEqual(
            SSHBridgePlugin._extract_command(_Event("ssh Get-Service sshd")),
            "Get-Service sshd",
        )

    def test_requires_command_boundary(self):
        self.assertEqual(
            SSHBridgePlugin._extract_command(_Event("sshstatus")), "sshstatus"
        )

    def test_plain_help_command(self):
        self.assertEqual(SSHBridgePlugin._extract_command(_Event("/ssh")), "")


class HandlerRegistrationTests(unittest.TestCase):
    def test_command_filter_runs_before_permission_filter(self):
        handler = star_handlers_registry.get_handler_by_full_name("main_ssh_cmd")
        self.assertIsNotNone(handler)
        filters = handler.event_filters
        self.assertIsInstance(filters[0], CommandFilter)
        self.assertIsInstance(filters[1], PermissionTypeFilter)


class LlmToolPermissionTests(unittest.TestCase):
    def test_llm_tool_rejects_non_admin(self):
        class _NonAdminEvent:
            def is_admin(self):
                return False

        result = asyncio.run(
            SSHBridgePlugin.ssh_bridge_exec(
                object(), _NonAdminEvent(), command="uptime"
            )
        )
        self.assertEqual(result, "该工具仅 AstrBot 管理员可用。")


if __name__ == "__main__":
    unittest.main()
