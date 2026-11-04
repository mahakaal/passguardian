# ADR 0005 – Argon2id parameters and the vault format

**Status:** accepted (Sprint 1). Completes [ADR 0003](0003-zero-knowledge-cryptography.md), which left the parameters and the choice between AEADs open.

**Context.** `passguardian-core` now implements the key hierarchy, item encryption and the serialized vault. This ADR records the choices that are baked into data users will keep for years, why they were made, and what is known to be missing.

## Decision

### 1. Key derivation: Argon2id, 64 MiB / 3 passes / 4 lanes

- Master password → **Argon2id** (version 0x13) → 256-bit master key.
- Default parameters for new vaults: **memory 64 MiB, 3 iterations, parallelism 4** (`KdfParams::DEFAULT`).
  - It is the *second recommended option* of [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), the "uniformly safe" choice for when much less memory is available. The first option (1 pass, 2 GiB) is not realistic on phones and browser extensions.
  - It is also Bitwarden's default, which keeps imported expectations and user experience comparable ([Bitwarden KDF documentation](https://bitwarden.com/help/kdf-algorithms/)).
  - Measured with the `core` implementation in a release build on a 2-vCPU cloud machine (median of 5 runs): 64 MiB / 3 / 4 ≈ **180 ms**; 128 MiB ≈ 380 ms; 256 MiB ≈ 740 ms. Phones and WebAssembly will be slower: see follow-up F2.
- The salt is chosen by the caller and must be at least **16 bytes** (`MIN_SALT_LEN`); shorter salts are rejected.
- The parameters are **stored in the vault document**, not hard-coded, so they can be raised later. Raising them means deriving a new master key and re-wrapping the vault key (section 2); no item is re-encrypted.
- Correctness is pinned by the RFC 9106 test vector (including its secret and associated data inputs) and by vectors from the reference `libargon2`.

### 2. Key hierarchy

```
master password ──Argon2id──► master key ──wraps──► vault key (random, 256-bit) ──encrypts──► items
```

- The vault key comes from the operating system's CSPRNG and is **never derived from the password**. Changing the master password or the KDF parameters therefore re-wraps one 32-byte key instead of re-encrypting the vault.
- The recovery key of ADR 0003 is not implemented yet.

### 3. Authenticated encryption: XChaCha20-Poly1305 only

- ADR 0003 allowed "XChaCha20-Poly1305 or AES-256-GCM". **Version 1 uses XChaCha20-Poly1305 only.**
  - Its 192-bit nonce makes **random nonces safe** without a counter. A counter would need shared state between devices that edit the same vault offline, which is exactly what we cannot have.
  - It is fast and constant-time in plain software, with no dependence on AES hardware instructions (mobile, WebAssembly).
  - Supporting a second cipher would double the surface to test and to get wrong.
- Sealed layout: `nonce (24 bytes) || ciphertext || tag (16 bytes)`, i.e. **40 bytes of overhead**. A fresh random nonce is drawn for every message.
- **Associated data** binds a ciphertext to its role:
  - wrapped vault key: `"passguardian/v1/vault-key"`;
  - item: `"passguardian/v1/item"` followed by the item identifier.

  A malicious server therefore cannot swap the contents of two items, nor replay the wrapped vault key as if it were an item; both fail authentication.
- Changing the cipher, the layout or any of these labels is an incompatible change: see section 4.

### 4. The vault document (format version 1)

```json
{
  "version": 1,
  "kdf": { "memory_kib": 65536, "iterations": 3, "parallelism": 4 },
  "salt": "<base64>",
  "wrapped_vault_key": "<base64>",
  "items": [ { "id": "<text>", "data": "<base64>" } ]
}
```

- Binary fields are standard base64. Everything secret in the document is already ciphertext; the rest are the parameters needed to open it.
- Loading rules (`VaultDocument::from_json`):
  - a `version` **newer** than the build understands is rejected, never guessed at;
  - an **older** one is migrated step by step (`n` → `n + 1`) to the current version;
  - **unknown fields are rejected**, so a typo or a downgrade cannot silently drop data.
- **A new version is required** whenever the layout, the KDF, the cipher, or the associated-data labels change in a way an older reader would misinterpret.
- Compatibility is enforced by a **frozen fixture** (`crates/core/tests/fixtures/vault-v1.json`) that every build must still open and decrypt. If that test fails, bump the version and add a migration; never edit the fixture.
- Honest status: `MIGRATIONS` is empty because version 1 is the only version that has ever existed. The migration engine is tested with a synthetic history, not with a real one.

### 5. Memory hygiene

- `MasterKey` and `VaultKey` are wiped when dropped and print as `<redacted>` in `Debug` output.
- Decrypted item contents are returned in a wrapper that wipes them on drop.
- The `argon2` crate is built with its `zeroize` feature, so its working memory is cleared after use.

## Known limitations

1. **The cipher library keeps an unwiped copy of the key.** `chacha20poly1305` 0.10 does not zeroize the key it holds inside the cipher object. That object lives only for one seal/open call, but a short-lived copy of the vault or master key can remain in process memory afterwards. Mitigation: none in our code; re-evaluate whenever the dependency is upgraded.
2. **No protection against swapping or core dumps.** Keys are not locked in RAM (`mlock`). That is platform-specific and belongs to the clients.
3. **The server learns metadata.** Item identifiers, the number of items and the size of each ciphertext are visible; contents are not. Sizes are not padded.
4. **Everything rests on the master password.** Argon2id slows down guessing; it does not make a weak password strong.
5. **No independent review.** The code follows standard constructions and published test vectors, but it has not been audited. An external audit is a gate before any 1.0 release (see `docs/roadmap.md`).

## Alternatives considered

| Option | Why not |
|---|---|
| PBKDF2-HMAC-SHA256 | Cheap on GPUs. May be offered later only to import or interoperate. |
| scrypt, bcrypt | Argon2id is the current standard recommendation and has an RFC. |
| AES-256-GCM | Needs a nonce strategy that is hard to keep safe across offline devices (see section 3). |
| Vault key derived directly from the password | A password change would force re-encrypting the whole vault. |
| 2 GiB Argon2id (RFC 9106 first option) | Not usable on phones and browser extensions. |

## Tests

See `docs/testing.md`, Sprint 1: known KDF vectors, wrap/unwrap, tamper rejection, nonce uniqueness, property tests on round trips, the frozen v1 fixture.

## Follow-ups

- **F1 – KDF parameter bounds.** Today `core` only enforces Argon2's own validity limits. A compromised server could hand a client weak parameters at login (easier offline guessing) or enormous ones (denial of service). Clients must enforce a **floor and a ceiling** before deriving. The numbers are set in the task that implements it, tests first.
- **F2 – Measure on real devices.** Re-measure on a low-end Android phone, an iPhone and WebAssembly in a browser, then confirm or revise the defaults before the first release.
- **F3 – Recovery key.** Specify its format and where it lives (ADR 0003 mentions it, nothing implements it).
- **F4 – Length hiding.** Decide whether to pad plaintext before encryption.
- **F5 – Key zeroization in the cipher library.** Revisit limitation 1 on every upgrade of `chacha20poly1305`.
