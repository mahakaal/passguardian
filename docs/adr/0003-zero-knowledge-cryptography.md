# ADR 0003 – Zero-knowledge cryptography

**Status:** accepted (parameters to be defined in Sprint 1)

**Decision.**
- Master password → **Argon2id** → master key. Parameters are stored and upgradable.
- The master key wraps a **random 256-bit vault key**.
- Items are encrypted with **XChaCha20-Poly1305** or AES-256-GCM, in a versioned format.
- Authentication: **OPAQUE** (`opaque-ke`), so the server never receives the master password or any direct derivative of it.
- Asymmetric cryptography (X25519) is used only for sharing between users.
- **No RSA for the vault.** No home-made cryptography.
- A recovery key is generated when the account is created.
