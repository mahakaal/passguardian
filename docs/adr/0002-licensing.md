# ADR 0002 – Licensing

**Status:** proposed (to be confirmed before the first release)

**Provisional decision.**
- `core`, `proto`: **MPL-2.0** (file-level copyleft, compatible with static linking in Rust/WASM/mobile).
- `server-*`, `server`, `cli`: **AGPL-3.0-or-later** (whoever offers the server as a service must publish their changes).
- Contributions under the **DCO**, no CLA.

**Alternatives.** GPLv3 for clients; Apache-2.0 for maximum adoption; LGPL rejected (relinking is a poor fit for Rust).
**Note.** With external contributions and no CLA, changing license later requires the consent of the contributors.
