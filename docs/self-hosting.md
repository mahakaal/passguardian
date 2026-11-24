# Self-hosting

PassGuardian is zero-knowledge: the server stores only ciphertext and a hash of a login key, so
losing or leaking the database does not reveal anybody's passwords. It still must be protected:
it decides who can fetch the ciphertext and who can delete it.

## Quick start (Docker Compose)

```sh
git clone https://github.com/mahakaal/passguardian && cd passguardian
cp .env.example .env
# fill POSTGRES_PASSWORD (openssl rand -hex 24) and PASSGUARDIAN_TOKEN_SECRET (openssl rand -base64 32)
docker compose up -d --build
curl http://127.0.0.1:8080/api/v1/health
```

The server listens on `127.0.0.1:8080` only. **Put a reverse proxy with TLS in front of it**
(Caddy, nginx, Traefik): the API must never be reachable over plain HTTP from outside.

Caddy example:

```
pass.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

## Using it

```sh
cargo install --path crates/cli            # installs the `passguardian` binary
export PASSGUARDIAN_SERVER=https://pass.example.org
passguardian register --email you@example.org
passguardian add GitHub --username you --generate
passguardian list
```

## Configuration

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | PostgreSQL URL (required). Migrations are applied at start. |
| `PASSGUARDIAN_BIND` | Listen address (default `127.0.0.1:8080`; the image sets `0.0.0.0:8080`). |
| `PASSGUARDIAN_TOKEN_SECRET` | base64 of ≥ 32 random bytes. Without it every restart logs everybody out. |
| `RUST_LOG` | Log level (default `info`). Logs never contain secrets. |

## Backup and restore

Back up the PostgreSQL database; nothing else holds state.

```sh
docker compose exec -T postgres pg_dump -U passguardian -Fc passguardian > backup.dump
# restore into an empty database:
docker compose exec -T postgres pg_restore -U passguardian -d passguardian --clean --if-exists < backup.dump
```

Backups contain ciphertext only, but keep them private anyway. Test a restore before you need it.
Keep a copy of your master password somewhere safe: it cannot be recovered.

## Known limits of this release

See ADR 0009: the login is not yet OPAQUE, refresh tokens are not rotated, and there is no
per-IP rate limit, so rely on your reverse proxy for that.
