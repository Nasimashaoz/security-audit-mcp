# Contributing to security-audit-mcp

Thank you for helping make AI-powered security auditing better! 🔐

## Ways to Contribute

### 📁 Add a New Framework
The most impactful contribution. We want to add:
- **PCI-DSS** (payment card security)
- **SOC 2 Type II** (service organization controls)
- **HIPAA Security Rule** (healthcare data)
- **CIS Controls v8** (Center for Internet Security)
- **GDPR** (EU data protection)

Frameworks live in `src/frameworks.ts`. Copy the existing structure and add your framework.

### 🐛 Report Bugs
Open an issue with:
- Your Node.js version
- Your MCP client (Claude Desktop / Cursor / other)
- Steps to reproduce
- Expected vs actual behavior

### 💡 Suggest Features
Open a feature request issue. Most wanted:
- CVE lookup integration
- Automated codebase scanning
- GitHub Actions integration
- Scoring benchmarks / compliance thresholds

## Pull Request Process

1. Fork the repo
2. Create a branch: `git checkout -b feature/pci-dss-framework`
3. Make changes
4. Test: `npm run build && npm start`
5. Open PR with clear description

## Code Style
- TypeScript strict mode
- Descriptive variable names
- JSDoc comments on exported functions

## Questions?
Open an issue — all questions welcome!
