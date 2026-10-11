# PassGuardian

**Open source**, **zero-knowledge**, **self-hosted** password manager, designed to be maintainable by the community.
Goal: an encrypted personal vault, sync across devices, password generator, autofill and passkeys.

> ⚠️ **Status: early development, not audited.** Do not use it for passwords that matter.

## Principles
- **Zero-knowledge:** the server only sees ciphertext. The master password never leaves the client.
- **Self-hosted first:** a single service (modular monolith) + PostgreSQL.
- **Separated layers:** `api` → `domain` ← `data`. See [docs/architecture.md](docs/architecture.md).
- **Test-first:** see [docs/testing.md](docs/testing.md).
- **Sprint roadmap:** see [docs/roadmap.md](docs/roadmap.md).

## Layout
| Crate | Role | License |
|---|---|---|
| `core` | client-side cryptography, vault format, generator, TOTP | MPL-2.0 |
| `proto` | shared API contract (DTOs) | MPL-2.0 |
| `server-domain` | use cases and repository traits (no I/O) | AGPL-3.0-or-later |
| `server-data` | PostgreSQL implementation + migrations | AGPL-3.0-or-later |
| `server-api` | Axum router, handlers, error mapping | AGPL-3.0-or-later |
| `server` | binary: configuration and wiring of the layers | AGPL-3.0-or-later |
| `cli` | command-line client | AGPL-3.0-or-later |

## Try it
```bash
cargo run -p passguardian-server        # listens on 127.0.0.1:8080 (PASSGUARDIAN_BIND)
curl http://127.0.0.1:8080/api/v1/health
cargo run -p passguardian-cli
```

## Development
```bash
bash scripts/verify.sh   # same checks as CI
```
Read [CONTRIBUTING.md](CONTRIBUTING.md). Security: [SECURITY.md](SECURITY.md).

## Support the project
If you find it useful you can support it with a donation (links to be added in `.github/FUNDING.yml` and here).

## License
Per crate, see the table above. License texts are in [LICENSES/](LICENSES/).
