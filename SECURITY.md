# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ (upgrade recommended) |

## Scope

Sentinel PE is a **static analysis tool that never executes samples or sends files to the network**. 

Security issues that are in scope:
- Malicious PE files that crash or hang the application (DoS via crafted input)
- Memory safety issues in the PE parser (buffer reads out of bounds)
- Renderer sandbox escapes in the Electron wrapper
- Sensitive data unintentionally exposed in logs or reports

Out of scope:
- Malware samples analyzed by the tool — the tool is designed to safely handle malicious files

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please email a report to the maintainers with:
- A description of the vulnerability
- Steps to reproduce (crafted PE file, if applicable — attach the file privately)
- Impact assessment
- Suggested fix if you have one

You will receive an acknowledgment within 48 hours and a resolution timeline within 7 days.

## Safe Handling

Sentinel PE reads PE files locally and does not execute them. However:
- Always work with malware samples in an isolated VM with no network access
- Never analyze untrusted files on production or personal machines
- Follow your organization's specimen handling policy
