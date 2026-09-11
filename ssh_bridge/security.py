from __future__ import annotations

import re
from collections.abc import Iterable
from enum import Enum


class CheckResult(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


COMMON_BLOCKED_PATTERNS: tuple[str, ...] = (
    r"\b(?:mkfs(?:\.\w+)?)\b",
    r"\bdd\s+.*\bif=/dev/",
    r"\b(?:shutdown|reboot|poweroff|halt)\b",
    r"\binit\s+0\b",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",
    r"(?:curl|wget)\b.*\|\s*(?:ba)?sh\b",
    r">\s*/dev/(?:sd[a-z]|nvme|vd[a-z]|hd[a-z])",
    r"\bkill\s+(-9\s+)?-1\b",
    r"(?:^|(?<=[;&|\n]))\s*(?:eval|exec)\b",
)

LINUX_BLOCKED_PATTERNS: tuple[str, ...] = (
    r"\brm\s+-[^\n]*(?:[rf][a-z]*[rf]|[a-z]*[rf])\b",
    r"\brm\s+/",
    r"\b(?:useradd|usermod|groupadd|passwd|chpasswd|visudo)\b",
    r"/etc/(?:sudoers|shadow)\b",
    r"\b(?:nc|ncat|socat)\s+-[lpe]\b",
    r"\bcron(?:tab)?\s+-[re]\b",
    r"\b(?:python\d*|perl|ruby|php)\s+(?:-[ci]\b|-[ce]\b)",
    r"\b(?:node|deno)\s+(?:-e|--eval)\b",
    r"\b(?:bash|sh|zsh|dash)\s+(?:-c|--command)\b",
    r"\bchmod\s+(-R\s+)?777\s+/(?:etc|usr|var|root|home|boot)\b",
    r"\bfind\b.*(?:\s-delete\b|\s-exec\b)",
    r"\b(?:iptables|nft|ufw|firewall-cmd)\b",
)

WINDOWS_BLOCKED_PATTERNS: tuple[str, ...] = (
    r"\b(?:Format-Volume|Format-Table\s+/?)\b.*\b(?:C:|D:)\b",
    r"\b(?:Clear-Disk|Initialize-Disk|Remove-Partition|Set-Disk)\b",
    r"\b(?:Restart-Computer|Stop-Computer)\b",
    r"\b(?:shutdown|logoff)\b",
    r"\b(?:del|rd|erase)\s+.*(?:/s|/q)\b",
    r"\bRemove-Item\b.*(?:-Recurse|-Force)",
    r"\b(?:Invoke-Expression|iex)\b",
    r"\bpowershell(?:\.exe)?\s+(?:-Command|-EncodedCommand)\b",
    r"\bcmd(?:\.exe)?\s+/(?:c|k)\b",
    r"\bnet\s+(?:user|localgroup)\b",
    r"\breg\s+(?:add|delete|import)\b",
    r"\b(?:schtasks|sc(?:\.exe)?)\s+(?:/create|/delete|create|delete)\b",
    r"\bSet-ExecutionPolicy\b",
    r"\b(?:Start-Process|New-Service)\b",
)

LINUX_DEFAULT_WHITELIST: tuple[str, ...] = (
    "cd",
    "pwd",
    "ls",
    "cat",
    "head -n",
    "tail -n",
    "grep",
    "find",
    "wc",
    "sort",
    "uniq",
    "df",
    "du",
    "free",
    "ps",
    "uptime",
    "uname",
    "whoami",
    "id",
    "hostname",
    "date",
    "echo",
    "printenv",
    "file",
    "stat",
    "which",
    "whereis",
    "lsblk",
    "lscpu",
    "lsof",
    "ss",
    "ip",
    "ifconfig",
    "ping -c",
    "traceroute",
    "dig",
    "nslookup",
    "dmesg",
    "journalctl -n",
    "systemctl status",
    "service --status-all",
    "docker ps",
    "docker images",
    "docker logs --tail",
    "docker stats --no-stream",
    "docker inspect",
    "git status",
    "git log",
    "git diff",
    "git branch",
    "git remote",
    "git show",
    "pip list",
    "pip show",
    "npm list",
    "node -v",
    "python --version",
    "python3 --version",
    "crontab -l",
    "last",
    "w",
    "who",
    "nginx -t",
    "curl -I",
)

WINDOWS_DEFAULT_WHITELIST: tuple[str, ...] = (
    "cd",
    "Get-Location",
    "Get-ChildItem",
    "Get-Content",
    "Get-Service",
    "Get-Process",
    "Get-NetTCPConnection",
    "Get-NetIPAddress",
    "Get-PSDrive",
    "Get-Volume",
    "Get-Disk",
    "Get-Partition",
    "Get-ComputerInfo",
    "Get-EventLog",
    "Get-WinEvent",
    "Get-Date",
    "Get-Command",
    "Get-Member",
    "Get-Help",
    "Select-String",
    "Select-Object",
    "Measure-Command",
    "Sort-Object",
    "Where-Object",
    "dir",
    "type",
    "whoami",
    "hostname",
    "ipconfig",
    "systeminfo",
    "tasklist",
    "netstat",
    "ping -n",
    "Test-NetConnection",
    "wsl -l",
    "wsl --status",
    "python --version",
    "node -v",
)

_SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|passphrase|token|api[_-]?key|"
            r"access[_-]?key|secret[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S+"
        ),
        "secret=***",
    ),
    (
        re.compile(r"(?i)\b(?:authorization|bearer)\s*[:=]?\s*\S+"),
        "authorization=***",
    ),
    (
        re.compile(
            r"-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
            r"-----END\s+[A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "***PRIVATE_KEY***",
    ),
    (
        re.compile(r"(?i)\b(?:mysql|postgres(?:ql)?|redis|mongodb)://\S+"),
        "***DB_URI***",
    ),
    (re.compile(r"(?<!\w)[A-Za-z0-9+/]{40,}={0,2}(?!\w)"), "***BASE64***"),
)


def sanitize_text(text: str) -> str:
    """Mask common credential formats before text is logged or sent."""
    for pattern, replacement in _SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def split_shell_commands(command: str) -> list[str]:
    """Split shell command chains while preserving quoted strings."""
    commands: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for index, char in enumerate(command):
        if escaped:
            current.append(char)
            escaped = False
            continue

        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            continue

        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue

        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue

        if char == "#" and (not current or current[-1].isspace()):
            break

        if char in {";", "&", "|", "\n"}:
            if char in {"&", "|"} and index + 1 < len(command) and command[index + 1] == char:
                commands.append("".join(current).strip())
                current = []
                # The next loop iteration consumes the second separator.
                continue
            commands.append("".join(current).strip())
            current = []
            continue

        current.append(char)

    commands.append("".join(current).strip())
    return [item for item in commands if item]


def _command_matches(command: str, allowed: str) -> bool:
    allowed_parts = allowed.strip().split()
    command_parts = command.strip().split()
    if not allowed_parts or not command_parts:
        return False

    candidates = [command_parts]
    if command_parts[0] == "sudo" and len(command_parts) > 1:
        candidates.append(command_parts[1:])

    for parts in candidates:
        if parts[: len(allowed_parts)] == allowed_parts:
            return True
    return False


def _has_command_substitution(command: str) -> bool:
    return "$(" in command or "`" in command


def check_command(
    command: str,
    platform: str,
    whitelist: Iterable[str] | None = None,
    *,
    allow_all: bool = False,
) -> CheckResult:
    """Classify a command as allowed, confirm-required, or blocked."""
    command = command.strip()
    if not command:
        return CheckResult.CONFIRM
    if allow_all:
        return CheckResult.ALLOW

    patterns = COMMON_BLOCKED_PATTERNS
    if platform == "windows":
        patterns += WINDOWS_BLOCKED_PATTERNS
    else:
        patterns += LINUX_BLOCKED_PATTERNS
    for pattern in patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return CheckResult.BLOCK

    if _has_command_substitution(command):
        return CheckResult.CONFIRM

    allowed_commands = tuple(item.strip() for item in (whitelist or ()) if item.strip())
    if not allowed_commands:
        allowed_commands = (
            WINDOWS_DEFAULT_WHITELIST if platform == "windows" else LINUX_DEFAULT_WHITELIST
        )

    for sub_command in split_shell_commands(command):
        if not any(_command_matches(sub_command, allowed) for allowed in allowed_commands):
            return CheckResult.CONFIRM

    return CheckResult.ALLOW
