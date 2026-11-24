# syntax=docker/dockerfile:1
# Multi-stage build of the PassGuardian server: a small image that runs as a non-root user.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p passguardian-server \
 && cp target/release/passguardian-server /passguardian-server

# distroless/cc: glibc and certificates, no shell, no package manager. UID 65532.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /passguardian-server /usr/local/bin/passguardian-server
ENV PASSGUARDIAN_BIND=0.0.0.0:8080
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/passguardian-server"]
