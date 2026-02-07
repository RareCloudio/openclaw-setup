# Contributing to OpenClaw Secure Setup

Thanks for your interest in making OpenClaw safer for everyone.

In January 2026, security researchers found **42,000+ OpenClaw instances exposed to the internet** with no authentication. This project exists to fix that — one VPS at a time.

## How You Can Help

### Report Security Issues

Found a vulnerability? Please **don't** open a public issue. Email hello@rarecloud.io instead. We'll credit you in the fix.

### Improve the Setup Script

The main file is `setup.sh`. Areas that need work:

- **More Linux distros** — Currently Ubuntu 24.04 only. Debian, RHEL, and Alpine support would help.
- **Better error handling** — The script should fail gracefully and tell users what went wrong.
- **Hardening improvements** — AppArmor profiles, seccomp filters, additional systemd sandboxing.
- **Testing** — Automated tests to verify the security measures actually work.

### Improve Documentation

- Translate README to other languages
- Add troubleshooting guides for common issues
- Write tutorials for specific hosting providers

## Before You Submit

1. **Test your changes** — Don't submit untested changes. Verify everything works on a fresh Ubuntu 24.04 installation.
2. **Keep it simple** — This script runs on people's servers. Complexity is the enemy of security.
3. **Don't break SSH** — Users get locked out if SSH changes fail. Be extra careful here.

## Code Style

- Bash with `set -euo pipefail`
- Functions for reusable logic
- Comments for non-obvious decisions
- Log messages prefixed with `[openclaw-setup]`

## Pull Request Process

1. Fork the repo
2. Create a branch (`git checkout -b fix/description`)
3. Make your changes
4. Test on a fresh Ubuntu 24.04 VPS
5. Submit PR with:
   - What you changed
   - Why it's needed
   - How you tested it

## Questions?

Open an issue or reach out at hello@rarecloud.io.

---

Every secured instance is one less target for attackers. Thanks for helping.
