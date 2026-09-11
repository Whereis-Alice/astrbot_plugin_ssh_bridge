from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import ssh_bridge.executor as executor_module
from ssh_bridge.executor import CommandTimeoutError, SSHSessionManager
from ssh_bridge.profiles import ProfileSet, ServerProfile


class _Connection:
    def __init__(self):
        self.create_process_kwargs = None

    async def create_process(self, command=None, **kwargs):
        self.create_process_kwargs = {"command": command, **kwargs}
        return object()


class _Session:
    def __init__(self):
        self.connection = _Connection()


class ExecutorTests(unittest.TestCase):
    @staticmethod
    def _profile(**overrides):
        values = {
            "name": "prod",
            "host": "203.0.113.10",
            "port": 22,
            "username": "deploy",
            "password": "secret",
            "private_key": "",
            "private_key_path": "",
            "private_key_passphrase": "",
            "platform": "linux",
            "execution_mode": "shell",
            "host_key_policy": "tofu",
            "encoding": "utf-8",
            "known_hosts_path": Path(tempfile.gettempdir())
            / "ssh-bridge-test-known-hosts",
            "command_whitelist": (),
        }
        values.update(overrides)
        return ServerProfile(**values)

    @staticmethod
    def _manager(**overrides):
        config = {
            "command_timeout": 1,
            "connect_timeout": 1,
            "max_output_bytes": 32,
            "max_lines": 2,
            "idle_timeout": 1,
            "history_size": 5,
        }
        config.update(overrides)
        return SSHSessionManager(
            ProfileSet((), "prod"), config, Path(tempfile.gettempdir())
        )

    def test_truncates_output_to_configured_lines(self):
        async def run():
            return await self._manager(max_lines=2)._truncate("a\nb\nc\n")

        output, truncated = asyncio.run(run())
        self.assertEqual(output, "b\nc")
        self.assertTrue(truncated)

    def test_run_timeout_is_user_safe(self):
        async def run():
            async def fail(*args, **kwargs):
                raise asyncio.TimeoutError()

            session = _Session()
            session.connection.run = fail
            return await self._manager()._execute_run(
                session, self._profile(), "sleep 10"
            )

        with self.assertRaises(CommandTimeoutError):
            asyncio.run(run())

    def test_shell_process_uses_profile_encoding_and_merged_stderr(self):
        async def run():
            manager = self._manager()
            profile = self._profile()
            captured = {}

            async def fake_prepare_host_key(server, lock):
                captured["server"] = server

            async def fake_connect(server):
                connection = _Connection()
                captured["connection"] = connection
                return connection

            old_prepare = executor_module.prepare_host_key
            old_connect = manager._connect
            executor_module.prepare_host_key = fake_prepare_host_key
            manager._connect = fake_connect
            try:
                session = await manager.get_or_create("admin", profile)
            finally:
                executor_module.prepare_host_key = old_prepare
                manager._connect = old_connect

            return session, captured["connection"]

        session, connection = asyncio.run(run())
        self.assertIsNone(connection.create_process_kwargs["command"])
        self.assertEqual(connection.create_process_kwargs["encoding"], "utf-8")
        self.assertEqual(connection.create_process_kwargs["errors"], "replace")
        self.assertEqual(
            connection.create_process_kwargs["stderr"],
            executor_module.asyncssh.STDOUT,
        )
        self.assertIsNotNone(session.process)


if __name__ == "__main__":
    unittest.main()
