# Security Policy

This project exists because OpenClaw deployments are frequently misconfigured and exposed. We take security seriously.

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

Email **hello@rarecloud.io** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We'll respond within 48 hours and work with you on a fix. Once resolved, we'll credit you in the release notes (unless you prefer to stay anonymous).

## Scope

This policy covers:

- The setup script (`setup.sh`)
- Firewall rules and configurations it creates
- systemd service definitions
- Any credentials or tokens generated

## Out of Scope

- OpenClaw itself (report to the OpenClaw team)
- Vulnerabilities in Ubuntu, Docker, or other dependencies
- Social engineering attacks

## Security Measures

This script implements an 8-layer security model:

| Layer | Protection |
|-------|------------|
| 1 | nftables firewall — only SSH allowed inbound |
| 2 | fail2ban — blocks brute-force attempts |
| 3 | SSH hardening — key-only auth, custom port, DenyUsers |
| 4 | Gateway token — 64-char authentication |
| 5 | AppArmor — process confinement |
| 6 | Docker sandbox — isolated agent execution |
| 7 | systemd — privilege restrictions |
| 8 | Screen lock — desktop auto-locks, password required via VNC |

If you find a way to bypass any of these layers, we want to know.

## Acknowledgments

Thanks to everyone who helps keep OpenClaw users safe:

- *Your name could be here*
