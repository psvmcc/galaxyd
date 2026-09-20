FROM rust:1.94.1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools ca-certificates && rm -rf /var/lib/apt/lists/*
RUN case "$(uname -m)" in x86_64) echo x86_64-unknown-linux-musl ;; aarch64|arm64) echo aarch64-unknown-linux-musl ;; *) exit 1 ;; esac > /tmp/rust-target && rustup target add "$(cat /tmp/rust-target)"
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_OPT_LEVEL=1 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=32 \
    cargo build --release --locked --target "$(cat /tmp/rust-target)" && \
    mkdir /out && cp "target/$(cat /tmp/rust-target)/release/galaxyd" /out/galaxyd

FROM scratch
COPY --from=builder /out/galaxyd /usr/local/bin/galaxyd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/galaxyd"]
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/galaxyd", "healthcheck", "--url", "http://127.0.0.1:9090/healthz"]
