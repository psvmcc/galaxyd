# galaxyd

galaxyd is a small Ansible Galaxy collection server written in Rust. It serves a read-only collection catalog and UI, accepts collection uploads into configured namespaces, and stores artifacts in a local directory or an S3-compatible bucket.

## Features

- TOML, YAML, and YML configuration;
- default configuration path /etc/galaxyd/galaxyd.toml;
- local-directory and S3-compatible storage;
- namespace-scoped Token and Bearer upload authentication;
- token rotation through one token per line in <token_dir>/<namespace>.secrets;
- namespace-specific publishing networks;
- nginx-style trusted X-Forwarded-For handling through set_real_ip_from;
- separate public and observability listeners;
- /healthz, /readyz, and Prometheus /metrics;
- SIGHUP configuration reload;
- embedded catalog UI with Gruvbox light/dark/system themes;
- shareable namespace and collection URLs;
- Podman and scratch image support;
- Rust tests and dependency license checks.

## Quick start

~~~bash
just check
just test
just run config=./config/galaxyd.example.toml
~~~

The example configuration uses local storage. The public listener defaults to `0.0.0.0:8080`; the observability listener defaults to `127.0.0.1:9090` and is available locally only.

Open http://localhost:8080/ for the embedded UI. The UI reads namespaces from configuration and collections from the read-only API.

For a complete configuration reference, see [CONFIGURATION.md](CONFIGURATION.md).

## Command line

~~~text
galaxyd [--config PATH]
galaxyd check-config [--config PATH]
galaxyd healthcheck --url http://127.0.0.1:9090/healthz
~~~

The default configuration path is /etc/galaxyd/galaxyd.toml.

~~~bash
just run
just run config=./config/galaxyd.example.toml
~~~

## Namespaces and tokens

A namespace is the Ansible collection namespace. For a namespace named engineering, create:

~~~text
/etc/galaxyd/tokens/engineering.secrets
~~~

The file contains one token per line:

~~~text
old-token
new-token
~~~

Blank lines and lines beginning with # are ignored. The server accepts:

~~~http
Authorization: Token new-token
Authorization: Bearer new-token
~~~

The server reads the file for each authorization decision. Adding a token enables it without a restart; removing a token revokes it for the next decision. Missing, unreadable, or empty files deny publishing for that namespace. Keep secrets readable only by the service (mode 0600 when owned by it, or 0640 with a dedicated service group), make secret directories non-writable by the service where possible, and never log secret contents.

Uploads are authorized before their body is processed, streamed into a temporary file, validated off the async runtime, and then streamed into local or S3 storage. Import task creation and publication finish independently of the HTTP connection. Graceful shutdown waits for these operations, including their final task status updates. Artifact downloads are streamed from storage. API timestamps are RFC3339 UTC strings without fractional seconds.

A token in one namespace's file does not authorize uploads to another namespace. The same token authorizes both only when it is explicitly present in both files.

Global authorization is disabled by default for compatibility; with this setting the configured catalog and collection archives are public. Enable `[auth].enabled` to require local administrator or OIDC login for the UI and browser API. Anonymous users then receive no namespace data. Ansible read access uses `<namespace>.read.secrets`; write tokens use `<namespace>.write.secrets` or the legacy `<namespace>.secrets`. Write tokens also permit read access, while RO tokens never permit publishing. Local administrator and OIDC sessions do not replace write tokens for publishing.

Complete authorization examples are provided in [`config/galaxyd.auth.local.example.toml`](config/galaxyd.auth.local.example.toml), [`config/galaxyd.auth.local.example.yaml`](config/galaxyd.auth.local.example.yaml), [`config/galaxyd.auth.oidc.example.toml`](config/galaxyd.auth.oidc.example.toml), and [`config/galaxyd.auth.oidc.example.yaml`](config/galaxyd.auth.oidc.example.yaml).

OIDC sessions request `offline_access` by default. Configure the provider to issue refresh tokens to this client, or set `request_offline_access = false` if that scope is unsupported. Register `server.public_url` plus `/auth/oidc/callback` as the redirect URI with the provider. On the first request after `refresh_interval_seconds` (default: 300), the server refreshes groups and replaces the session's permissions. A rejected refresh token or missing refresh token ends the session; the user must sign in again. A temporary provider error returns `503` for the protected request and keeps the session for a later retry without granting access using stale rights. Role changes may take longer than the interval if the provider caches group membership. A session still ends at `session_ttl_seconds` even when refresh succeeds.

## Publishing networks and forwarded IPs

push_networks restricts the effective client address for publishing. If it is omitted or empty, any client address may publish after token authorization.

set_real_ip_from is the trusted-proxy list and defaults to empty. X-Forwarded-For is considered only when the direct TCP peer belongs to one of these networks. The chain is resolved from right to left using recursive nginx-style behavior. A malformed, empty, missing, duplicated, or oversized forwarding header from a trusted proxy causes a publishing request to fail closed. Configure only the exact addresses or narrow subnets of your proxies; do not trust an entire private network.

When the server is directly exposed, leave set_real_ip_from empty. When it is behind nginx, list only the nginx addresses or networks and configure nginx to send X-Forwarded-For.

## API and UI

The default API prefix is /api/galaxy/.

~~~text
GET /api/galaxy/
GET /api/galaxy/v3/namespaces
GET /api/galaxy/v3/collections
GET /api/galaxy/v3/collections/{namespace}/{name}/
GET /api/galaxy/v3/collections/{namespace}/{name}/versions/
GET /api/galaxy/v3/collections/{namespace}/{name}/versions/{version}/
GET /api/galaxy/v3/artifacts/{namespace}/{name}/{version}/
POST /api/galaxy/v3/artifacts/collections/
~~~

The UI uses URLs that can be copied and shared:

~~~text
/?namespace=engineering
/?namespace=engineering&collection=common
~~~

The browser title follows the selected location:

~~~text
galaxyd
galaxyd - engineering
galaxyd - engineering.common
~~~

## Health, metrics, and logs

The observability listener exposes /healthz, /readyz, and /metrics.

Logs use tracing and are written to standard output. Use RUST_LOG to change the level:

~~~bash
RUST_LOG=debug just run config=./config.yaml
~~~

## Reload

~~~bash
kill -HUP $(pgrep galaxyd)
~~~

Invalid configuration leaves the active configuration unchanged. Token files are read independently and do not require a process restart.

## Container

~~~bash
just container-build
just container-run
~~~

The runtime image is scratch, runs as a numeric non-root user, and includes the CA bundle required for HTTPS S3 endpoints. Mount configuration, token files, and local storage into the container. TLS for incoming traffic is expected to terminate in nginx or another reverse proxy.

The supplied image builds a native static binary for x86_64 or AArch64. Run one active galaxyd process for each local storage root or S3 bucket prefix. Publication records are the visibility boundary: an artifact is downloadable only after its immutable JSON record has been committed. Completed import tasks are persisted in the configured backend and remain pollable after restart. On restart, unfinished tasks are reconciled immediately against committed records. The main branch publishes the `latest` container tag; releases publish versioned tags only.

The compatibility tests target the Galaxy v3 response fields consumed by `ansible-core` 2.19. Before supporting another client release, add it to the publish/install interoperability matrix and verify its exact API contract.

## Development commands

~~~bash
just fmt
just check
just test
just test-e2e
just test-ui
just lint
just license-check
just coverage
just build
just container-build
~~~

just coverage requires cargo-llvm-cov.

## License

galaxyd is licensed under the MIT License. See [LICENSE](LICENSE).
