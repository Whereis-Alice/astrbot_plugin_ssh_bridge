# SSH Bridge

![SSH Bridge](logo.png)

SSH Bridge 是一个 AstrBot 服务器运维插件。管理员可以在聊天里连接多台 Linux 或 Windows 服务器，执行安全检查后的命令，查看状态、诊断连接，并让 LLM 调用白名单内的运维命令。

它适合这些场景：

- 日常维护云服务器，例如查看 CPU、内存、磁盘、进程、Docker 和服务状态。
- 以后新增或迁移服务器时，直接添加新的服务器档案，不需要改插件代码。
- 帮别人排查 Windows 电脑问题，前提是对方启用 OpenSSH Server，并且 AstrBot 服务器能连到它。

## 快速开始

1. 在 AstrBot 插件安装界面填入仓库地址：

   ```text
   https://github.com/Whereis-Alice/astrbot_plugin_ssh_bridge
   ```

2. 安装完成后进入插件配置，添加一个服务器档案。
3. 至少填写 `name`、`host`、`username`，并在 `password`、`private_key_path`、`private_key` 中选择一种认证方式。
4. 保存配置后发送：

   ```text
   /ssh doctor
   ```

   返回 `whoami` 和 `hostname` 就说明连接成功。

## 指令

所有指令仅 AstrBot 管理员可用。`/` 前缀请按你的 AstrBot 唤醒配置调整。

| 指令 | 说明 |
| --- | --- |
| `/ssh <命令>` | 在当前服务器执行命令 |
| `/ssh use <名称>` | 切换服务器，并断开旧会话 |
| `/ssh servers` | 列出已配置的服务器 |
| `/ssh status` | 查看当前服务器和会话状态 |
| `/ssh doctor` | 连接当前服务器并返回 `whoami`、`hostname` |
| `/ssh log [条数]` | 查看最近执行记录，默认 5 条 |
| `/ssh out` | 断开当前服务器会话 |
| `/ssh yes` | 确认执行待确认命令 |
| `/ssh no` | 取消待确认命令 |
| `/ssh help` | 查看帮助 |

示例：

```text
/ssh use prod
/ssh uptime
/ssh df -h
/ssh docker ps
/ssh use win-pc
/ssh Get-Service sshd
```

## 多服务器配置

插件配置中的 `servers` 是服务器档案列表。每个档案都是独立配置，至少需要：

| 字段 | 说明 |
| --- | --- |
| `name` | 唯一名称，用于 `/ssh use` 和 LLM 工具 |
| `host` | 服务器 IP 或域名 |
| `port` | SSH 端口，默认 `22` |
| `username` | SSH 用户名 |
| `password` | 密码认证 |
| `private_key_path` | 私钥文件路径认证 |
| `private_key` | 直接粘贴私钥内容认证 |
| `platform` | `linux` 或 `windows` |
| `encoding` | 远端输出编码，默认 `utf-8`；中文 Windows 可尝试 `gbk` 或 `gb18030` |
| `execution_mode` | `auto`、`shell` 或 `run` |
| `host_key_policy` | `tofu` 或 `strict` |
| `enabled` | 是否启用该服务器 |

认证方式三选一：密码、私钥文件、私钥内容。私钥和密码同时存在时，优先使用私钥。

`execution_mode` 的区别：

- `auto`：Linux 默认使用 `shell`，Windows 默认使用 `run`。
- `shell`：保持一个远端 Shell，`cd`、`export` 等状态会延续；适合 Linux 日常运维。
- `run`：每条命令独立执行，不保留上下文；输出和退出码更稳定，适合 Windows 或脚本型命令。

`default_server` 留空时使用第一个启用的服务器。切换服务器只影响当前管理员，不会改变其他管理员的当前服务器。

## 安全策略

这个插件能真实执行远端命令，请只连接你有权管理的服务器。

默认策略分三层：

1. 黑名单：明显破坏性的命令直接拒绝，例如删除根路径、格式化磁盘、关机重启、执行下载脚本、修改 sudoers 等。
2. 白名单：只读运维命令直接执行，例如 `df`、`ps`、`systemctl status`、`docker ps`、`Get-Service`。
3. 二次确认：不在白名单中的命令会暂停，需要管理员在确认有效期内发送 `/ssh yes`。

LLM 工具 `ssh_bridge_exec` 只能执行白名单命令，不会自动执行需要确认的命令。默认白名单按 `platform` 区分 Linux 和 Windows。

其他安全行为：

- 插件指令仅管理员可用。
- 首次连接默认使用 TOFU 记录主机密钥，之后主机密钥变化会拒绝连接。
- `known_hosts` 默认保存在 AstrBot 插件数据目录，不会污染插件源码目录。
- 单条命令有长度、输出大小、输出行数和执行时长限制。
- 历史记录和聊天输出会遮蔽常见密码、Token、私钥、数据库 URI 和长 Base64 字符串。
- `enable_dangerous_commands=true` 会关闭所有命令检查，只建议临时排查时短暂开启。

如果服务器重装导致主机密钥变化，AstrBot 日志会出现 Host key is not trusted。请确认这是预期变化后，删除 `known_hosts` 中对应主机那一行，再重新连接。

## Windows 支持

可以连接 Windows，前提有两个：

1. 目标 Windows 启用了 OpenSSH Server。
2. AstrBot 所在机器能通过网络访问目标 Windows 的 SSH 端口。

在目标 Windows 上用管理员 PowerShell 执行：

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

Windows 防火墙通常会自动放行 `sshd`。如果没有放行：

```powershell
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server" `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

建议把默认 Shell 设置为 PowerShell，这样可以直接使用 `Get-Service`、`Get-Process` 等命令。下面会优先使用 PowerShell 7，未安装时回退到 Windows 自带 PowerShell：

```powershell
New-Item -Path HKLM:\SOFTWARE\OpenSSH -Force
$shell = "C:\Program Files\PowerShell\7\pwsh.exe"
if (-not (Test-Path $shell)) {
  $shell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
}
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH `
  -Name DefaultShell `
  -Value $shell `
  -PropertyType String -Force
Restart-Service sshd
```

插件配置中把该服务器设置为：

```text
platform: windows
execution_mode: auto
```

如果对方电脑在家庭或公司内网，AstrBot 云服务器通常不能直接访问它。可选方案：

- 同一局域网或 VPN 内使用。
- 使用 Tailscale、ZeroTier 等私有组网工具。
- 由对方主动建立反向 SSH 隧道。
- 在路由器上做端口转发，并使用强密钥、非默认端口和防火墙限制来源 IP。

不要把 Windows SSH 直接长期暴露在公网。SSH 只能连接已经启用服务且网络可达的机器，不能绕过 NAT 或未授权访问别人的电脑。

## LLM 工具

插件注册 `ssh_bridge_exec`，仅管理员会话可用，模型只能执行白名单内命令。

示例提问：

```text
看一下 prod 服务器的 CPU 和内存情况
列出当前 Docker 容器
检查 sshd 服务是否在运行
```

工具参数：

| 参数 | 说明 |
| --- | --- |
| `command` | 要执行的 Linux Shell 或 PowerShell 命令 |
| `server` | 可选服务器名称，留空使用当前服务器 |

## 常见问题

### 连接失败怎么办？

1. 发送 `/ssh doctor`。
2. 检查服务器档案中的地址、端口、用户名和认证方式。
3. 在 AstrBot 所在机器上测试 `ssh 用户名@主机 -p 端口`。
4. 查看 AstrBot 日志中的连接错误类型。

### 为什么命令需要确认？

命令不在当前服务器的白名单中。你可以发送 `/ssh yes` 确认，或在配置里为这台服务器添加更精确的命令前缀，例如 `docker logs --tail`。

不要为了省事直接添加 `docker`、`powershell`、`bash` 这类过宽前缀；它们会显著扩大可执行范围。

### 可以和原版 astrbot_plugin_ssh 同时启用吗？

不建议。两者都使用 `/ssh` 指令，同时启用会发生指令冲突。请先停用或卸载原插件，再启用 SSH Bridge。

### 原插件配置会自动迁移吗？

不会。SSH Bridge 使用新的插件名和新的配置结构。请在 WebUI 中按新的服务器档案格式重新填写连接信息，这样可以同时支持多台服务器。

## 开发与测试

```powershell
python -m pip install -r requirements.txt
python -m compileall .
python -m unittest discover -s tests -v
```

测试使用单元测试和 mock，不会连接真实服务器。

## 许可证

本项目基于 [astrbot_plugin_ssh](https://github.com/HSOS6/astrbot_plugin_ssh) 修改，继续采用 GNU Affero General Public License v3.0。见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
