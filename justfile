default:
    just --list

fmt:
    cargo fmt --all -- --check

check:
    cargo check --all-targets

test:
    cargo test --all-targets

lint:
    cargo clippy --all-targets --all-features -- -D warnings

license-check:
    cargo deny check

build:
    cargo build --release

run config="/etc/galaxyd/galaxyd.toml":
    cargo run -- --config "{{config}}"

container-build:
    podman build -f Containerfile -t galaxyd:dev .

container-run:
    podman run --rm -p 8080:8080 -p 9090:9090 -v "{{justfile_directory()}}/config/galaxyd.example.toml:/etc/galaxyd/galaxyd.toml:ro" -v "{{justfile_directory()}}/data:/var/lib/galaxyd:Z" galaxyd:dev

test-e2e:
    cargo test --test api

test-ui:
    cargo test ui

coverage:
    cargo llvm-cov --all-targets --html --open
