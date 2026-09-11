from __future__ import annotations

import asyncio
import importlib
import sys
import types
import unittest
from pathlib import Path

from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.permission import PermissionTypeFilter
from astrbot.core.star.star_handler import star_handlers_registry

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_PACKAGE = "data.plugins.astrbot_plugin_ssh_bridge"


def _import_plugin_main():
    """Import main.py using AstrBot's actual dotted plugin path."""
    if PLUGIN_PACKAGE not in sys.modules:
        for name in ("data", "data.plugins"):
            if name not in sys.modules:
                parent = types.ModuleType(name)
                parent.__path__ = []
                sys.modules[name] = parent

        package = types.ModuleType(PLUGIN_PACKAGE)
        package.__path__ = [str(PLUGIN_ROOT)]
        sys.modules[PLUGIN_PACKAGE] = package

    return importlib.import_module(f"{PLUGIN_PACKAGE}.main")


SSHBridgePlugin = _import_plugin_main().SSHBridgePlugin


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
        handler = star_handlers_registry.get_handler_by_full_name(
            f"{PLUGIN_PACKAGE}.main_ssh_cmd"
        )
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
