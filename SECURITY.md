# Security Policy

We take archive safety seriously. Please follow these guidelines when reporting vulnerabilities.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `main`  | ✅        |
| `dev` branch snapshots | ✅ |
| Released tags (`v0.x.y`) | ✅ while the branch receives security fixes |
| Anything older | ❌ |

We aim to backport critical fixes to the latest release and `main`.

## Reporting a Vulnerability

1. **Do not open a public issue.**
2. Email `security@safetar.dev` with a detailed report. Include:
   - Description of the issue and potential impact
   - Reproduction steps or proof of concept
   - Affected commit or release tag
   - Suggested mitigations if available
3. You will receive an acknowledgement within **3 business days**.
4. We will coordinate on a fix and set a disclosure timeline (usually ≤ 30 days).
5. Once a patch is available, we will publish a security advisory and credit you (optional).

If SLOs are missed or communication stalls, please escalate via `@your-org/security` on GitHub.

## Coordinated Disclosure & CVEs

- We follow responsible disclosure and request a short embargo until fixes are released.
- Upon agreement we will request a CVE ID (through GitHub Security Advisories or CERT/CC depending on scope).
- Public disclosure happens only after a patched release is available.

## Security Hardening Expectations

- Run safetar with the default security policy (`--strict` for automation).
- Validate manifests for supplied archives.
- Keep dependencies up to date (`cargo audit`, watch advisories).
- Use the `--print-plan` dry-run capability for CI/CD audits.
