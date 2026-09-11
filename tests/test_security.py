from __future__ import annotations

import unittest

from ssh_bridge.security import (
    CheckResult,
    check_command,
    sanitize_text,
    split_shell_commands,
)


class CommandSafetyTests(unittest.TestCase):
    def test_linux_default_whitelist(self):
        self.assertEqual(check_command("df -h", "linux"), CheckResult.ALLOW)
        self.assertEqual(
            check_command("systemctl status nginx", "linux"), CheckResult.ALLOW
        )

    def test_windows_default_whitelist(self):
        self.assertEqual(check_command("Get-Service sshd", "windows"), CheckResult.ALLOW)
        self.assertEqual(
            check_command("Get-Process | Select-Object -First 5", "windows"),
            CheckResult.ALLOW,
        )

    def test_unknown_command_needs_confirmation(self):
        self.assertEqual(
            check_command("curl https://example.com", "linux"), CheckResult.CONFIRM
        )

    def test_destructive_commands_are_blocked(self):
        self.assertEqual(check_command("rm -rf /", "linux"), CheckResult.BLOCK)
        self.assertEqual(
            check_command("Remove-Item C:\\Temp -Recurse -Force", "windows"),
            CheckResult.BLOCK,
        )

    def test_command_substitution_needs_confirmation(self):
        self.assertEqual(check_command("echo $(whoami)", "linux"), CheckResult.CONFIRM)

    def test_pipeline_is_checked_per_command(self):
        self.assertEqual(
            check_command("df -h | curl https://example.com", "linux"),
            CheckResult.CONFIRM,
        )

    def test_split_preserves_quotes_and_comments(self):
        self.assertEqual(
            split_shell_commands("echo 'a;b' && df -h # trailing comment"),
            ["echo 'a;b'", "df -h"],
        )

    def test_sanitize_masks_secrets(self):
        text = sanitize_text("password=hunter2 token=abc123")
        self.assertNotIn("hunter2", text)
        self.assertNotIn("abc123", text)


if __name__ == "__main__":
    unittest.main()
