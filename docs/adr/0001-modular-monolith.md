# ADR 0001 – Modular monolith

**Status:** accepted

**Context.** The target audience runs the server at home or on a small VPS. The service only handles encrypted blobs.

**Decision.** A single binary with separate modules (`api`, `domain`, `data`). No microservices.
Kubernetes is used for deployment only (Helm), not for the architecture.

**Consequences.** Simple installation and a smaller attack surface. A service is extracted only for a concrete reason.
