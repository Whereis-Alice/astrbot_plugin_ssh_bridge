from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ssh_bridge.profiles import ProfileError, load_profiles


class LoadProfilesTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def _server(**overrides):
        server = {
            "name": "prod",
            "host": "203.0.113.10",
            "username": "deploy",
            "password": "secret",
            "platform": "linux",
        }
        server.update(overrides)
        return server

    def test_loads_profiles_and_selects_default(self):
        profiles = load_profiles(
            {
                "servers": [self._server(), self._server(name="win", platform="windows")],
                "default_server": "win",
            },
            self.data_dir,
        )

        self.assertEqual(profiles.default_server, "win")
        self.assertEqual([item.name for item in profiles.servers], ["prod", "win"])
        self.assertEqual(profiles.get("win").encoding, "utf-8")
        self.assertEqual(profiles.get("win").resolved_execution_mode, "run")

    def test_uses_global_whitelist_fallback(self):
        profiles = load_profiles(
            {
                "servers": [self._server()],
                "command_whitelist": ["uptime", "df -h"],
            },
            self.data_dir,
        )

        self.assertEqual(profiles.get("prod").command_whitelist, ("uptime", "df -h"))

    def test_rejects_invalid_profile(self):
        with self.assertRaises(ProfileError):
            load_profiles(
                {"servers": [self._server(name="bad name")]},
                self.data_dir,
            )

        with self.assertRaises(ProfileError):
            load_profiles(
                {"servers": [self._server(encoding="not-an-encoding")]},
                self.data_dir,
            )

        with self.assertRaises(ProfileError):
            load_profiles({"servers": [self._server(name="")]}, self.data_dir)


if __name__ == "__main__":
    unittest.main()
