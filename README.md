# 🔐 security-audit-mcp

[![npm version](https://img.shields.io/npm/v/security-audit-mcp.svg?style=flat)](https://www.npmjs.com/package/security-audit-mcp)
[![npm downloads](https://img.shields.io/npm/dm/security-audit-mcp.svg?style=flat)](https://www.npmjs.com/package/security-audit-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-blueviolet)](https://modelcontextprotocol.io)
[![Claude](https://img.shields.io/badge/Works%20with-Claude-orange)](https://claude.ai)
[![Cursor](https://img.shields.io/badge/Works%20with-Cursor-blue)](https://cursor.sh)

> **Give your AI agent a security brain.** Run structured OWASP, NIST, and ISO 27001 audits directly inside Claude, Cursor, or any MCP-compatible AI agent — in seconds.

---

## ⚡ One-Line Install

```bash
npx security-audit-mcp
```

Or install globally:

```bash
npm install -g security-audit-mcp
```

---

## 🎟️ What This Does

`security-audit-mcp` is a **Model Context Protocol (MCP) server** that gives AI agents like Claude and Cursor the ability to:

- 🔍 **Run security audits** against OWASP Top 10, NIST SP 800-53, ISO 27001
- 🚨 **Identify risks** with CRITICAL / HIGH / MEDIUM / LOW severity scoring
- 📊 **Generate audit reports** in JSON, CSV, or HTML format
- 🧠 **Answer security questions** with structured framework knowledge
- ✅ **Check compliance gaps** for any application or infrastructure

Your AI agent goes from *"I can suggest security improvements"* to *"I can run a full structured OWASP audit on your codebase right now."*

---

## 🚀 Quick Setup

### Claude Desktop

Add this to your Claude Desktop config file:

**Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "npx",
      "args": ["-y", "security-audit-mcp"]
    }
  }
}
```

Restart Claude Desktop. You'll see `security-audit` in your tools list. ✅

### Claude Code (CLI)

```bash
claude mcp add security-audit -- npx -y security-audit-mcp
```

### Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "npx",
      "args": ["-y", "security-audit-mcp"]
    }
  }
}
```

### Any MCP-Compatible Agent

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "npx",
      "args": ["-y", "security-audit-mcp"]
    }
  }
}
```

---

## 🧠 Available MCP Tools

Once installed, your AI agent gets these tools:

| Tool | Description |
|------|-------------|
| `list_frameworks` | List all available security frameworks |
| `get_framework` | Get full checklist for a framework (owasp / nist / iso27001) |
| `audit_item` | Assess a specific control item with pass/fail/skip + notes |
| `generate_report` | Generate a full audit report from session results |
| `get_risk_summary` | Get a summary of risks by severity level |
| `search_controls` | Search controls by keyword across all frameworks |

### Example AI Prompts

Once installed, just talk to your AI agent:

```
"Run an OWASP Top 10 audit on my Express.js app"
"Check my infrastructure against NIST SP 800-53 controls"
"What are the CRITICAL risks in ISO 27001 I should fix first?"
"Generate an HTML security audit report for our staging environment"
"Search for all controls related to authentication across frameworks"
```

---

## 📊 Frameworks Included

### OWASP Top 10 (2021)
The 10 most critical web application security risks. Used by 90% of security teams worldwide.

### NIST SP 800-53 Rev 5
Federal security and privacy controls. Required for US government systems, widely adopted in enterprise.

### ISO 27001:2022
International standard for information security management. Required for ISO certification.

### PCI-DSS v4.0
Payment Card Industry Data Security Standard for protecting payment account data.

### SOC 2 Type II
Service Organization Control 2 framework focusing on security, availability, processing integrity, confidentiality, and privacy.

### HIPAA Security Rule
Health Insurance Portability and Accountability Act standards for protecting electronic protected health information (ePHI).

### CIS Controls v8
Center for Internet Security Critical Security Controls.

### GDPR
General Data Protection Regulation standards for data privacy and security.

---

## 🔧 Local Development

```bash
git clone https://github.com/Nasimashaoz/security-audit-mcp
cd security-audit-mcp
npm install
npm run build
npm start
```

### Run with MCP Inspector

```bash
npx @modelcontextprotocol/inspector node dist/index.js
```

---

## 🤝 Contributing

Want to add a new framework (CIS Controls, PCI-DSS, SOC 2, HIPAA)? PRs welcome!

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 💬 Community & Support

- 🐛 [Report a bug](https://github.com/Nasimashaoz/security-audit-mcp/issues)
- 💡 [Request a feature](https://github.com/Nasimashaoz/security-audit-mcp/issues)
- ⭐ [Star this repo](https://github.com/Nasimashaoz/security-audit-mcp) if it helps!

---

## 📄 License

MIT — free for personal and commercial use.

---

## 🚀 Roadmap

- [ ] Automated codebase scanning
- [ ] CI/CD pipeline integration (GitHub Actions)

---

> Built with ❤️ by [Nasima Shaoz](https://github.com/Nasimashaoz) — Cybersecurity Professional & OSS Maintainer
