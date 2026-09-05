# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/iA7maz/pqsum/security/advisories/new)
rather than opening a public issue.

## Supported versions

pqsum is pre-1.0. Only the latest release receives fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Threat model

Before relying on pqsum, read **[docs/SECURITY.md](docs/SECURITY.md)**. It
sets out what a pqsum signature does and does not prove, and documents known
gaps — in particular that pqsum does not solve key distribution, has no
revocation or expiry, and stores private keys unencrypted at rest.
