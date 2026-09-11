# Changelog

## v2.0.0

- Renamed the plugin to `astrbot_plugin_ssh_bridge` with a new identity and logo.
- Added multi-server profiles and per-admin server switching.
- Added Windows OpenSSH support with a Windows command whitelist.
- Added `run` execution mode for stable one-shot commands.
- Replaced silence-based interactive output detection with completion markers.
- Added connection diagnosis, status, server list, and richer help commands.
- Moved generated `known_hosts` data to the AstrBot plugin data directory.
- Added command timeout, output limits, history limits, and confirm timeout settings.
- Tightened default command safety rules and masked sensitive output.
- Fixed command filter ordering and added an in-tool administrator check for LLM calls.
- Added unit tests for profiles and command safety.
- Rewrote the public documentation and retained the upstream AGPL-3.0 notice.

## Upstream v1.5.x

See the original project history at <https://github.com/HSOS6/astrbot_plugin_ssh>.
