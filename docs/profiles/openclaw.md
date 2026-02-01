---
title: OpenClaw
description: Sandboxing OpenClaw gateway and agents with nono
---

[OpenClaw](https://openclaw.ai) is a multi-channel AI agent platform that enables chat interactions across WhatsApp, Telegram, Discord, and Mattermost. Because OpenClaw agents process external messages and can execute code, running them under nono provides OS-level isolation that cannot be bypassed.

## Why Sandbox OpenClaw?

OpenClaw agents receive messages from external users and can execute commands on the host system. Without proper isolation:

- A malicious message could trick an agent into accessing sensitive files
- Compromised agent code could exfiltrate credentials from `~/.openclaw/`
- An agent could be used as a pivot point to attack other systems on the network

nono's kernel-enforced sandbox ensures that even if an agent is compromised, it cannot exceed its granted capabilities.

## Recommended Profile

```toml
[meta]
name = "openclaw"
version = "1.0.0"
description = "OpenClaw messaging gateway and agents"

[filesystem]
allow = ["$WORKDIR"]
read = ["$HOME/.openclaw"]

[filesystem.files]
read = [
  "$HOME/.gitconfig"
]

[network]
block = false  # Required for messaging APIs

[secrets]
# Load API keys from system keystore instead of files
openai_api_key = "OPENAI_API_KEY"
anthropic_api_key = "ANTHROPIC_API_KEY"
```

**Usage:**
```bash
nono run --profile openclaw -- openclaw
```

## Security Tips

### Protect Credentials

OpenClaw stores sensitive data in `~/.openclaw/` including:
- Channel authentication tokens (WhatsApp sessions, Telegram bot tokens)
- OAuth credentials
- API keys for AI providers

The recommended profile grants **read-only** access to this directory. Agents can read their configuration but cannot modify or exfiltrate credentials to new locations.

For maximum security, use nono's secrets management to load API keys from the system keystore:

```bash
# Store secrets in system keystore (once)
nono secret set openai_api_key
nono secret set anthropic_api_key

# Run with secrets loaded from keystore
nono run --profile openclaw --secrets -- openclaw
```

This way, credentials never touch the filesystem where an agent could read them.

### Limit Agent Filesystem Access

By default, the profile grants read+write to the current working directory. For tighter control:

```bash
# Restrict to specific project directory only
nono run --profile openclaw --allow ~/projects/my-agent -- openclaw

# Block all writes, read-only mode
nono run --profile openclaw --read . -- openclaw
```

### Network Considerations

OpenClaw requires network access to communicate with:
- Messaging platform APIs (WhatsApp, Telegram, Discord, Mattermost)
- AI provider APIs (OpenAI, Anthropic, etc.)
- Optional web search APIs (Brave Search)

The profile allows full network access. Future nono versions will support per-host filtering to restrict connections to only required endpoints.

### Running as a Daemon

When running OpenClaw as a system service, wrap the daemon command with nono:

**macOS (launchd):**
```xml
<key>ProgramArguments</key>
<array>
  <string>/usr/local/bin/nono</string>
  <string>run</string>
  <string>--profile</string>
  <string>openclaw</string>
  <string>--</string>
  <string>openclaw</string>
  <string>daemon</string>
</array>
```

**Linux (systemd):**
```ini
[Service]
ExecStart=/usr/local/bin/nono run --profile openclaw -- openclaw daemon
```

### Combine with OpenClaw's Built-in Sandbox

OpenClaw has its own sandboxing option for group/channel sessions. Layer both for defense in depth:

1. **nono**: OS-level isolation (Landlock/Seatbelt) - cannot be bypassed by code
2. **OpenClaw sandbox**: Application-level isolation - easier to configure per-agent

```bash
# Both layers active
nono run --profile openclaw -- openclaw --sandbox
```

## Strict Mode Example

For high-security deployments where agents should have minimal access:

```bash
nono run \
  --read ~/.openclaw \
  --read ~/agents/my-agent \
  --allow ~/agents/my-agent/workspace \
  --secrets \
  -- openclaw
```

This configuration:
- Reads config from `~/.openclaw` (no writes)
- Reads agent code from `~/agents/my-agent`
- Only allows writes to the workspace subdirectory
- Loads secrets from keystore instead of files
