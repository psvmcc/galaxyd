# galaxyd Implementation Plan

## 1. Objective

Implement `galaxyd`, a small self-contained Ansible Galaxy-compatible server written in Rust.

The first release will provide:

- static TOML and YAML configuration;
- collection publishing and downloading;
- local-directory and S3-compatible object storage;
- namespace-scoped `Token` and `Bearer` authentication;
- namespace-specific source-network restrictions for publishing;
- separate API and observability listeners;
- health, readiness, and Prometheus metrics endpoints;
- embedded HTML/CSS/JavaScript web UI consuming the public read-only JSON API;
- configuration reload through `SIGHUP`;
- a minimal Podman-built `scratch` container image;
- automated tests and dependency/license checks.

The implementation should target the Galaxy NG v3 API shape required by `ansible-galaxy`, while keeping the internal model and storage abstraction deliberately smaller than a full Galaxy NG deployment.

## 2. Repository and toolchain

Create a new Rust workspace with one binary crate named `galaxyd`.

Use:

- stable Rust;
- Tokio for async runtime and signal handling;
- Axum and Tower for HTTP routing and middleware;
- Serde for configuration and API models;
- `toml` and a maintained Serde-compatible YAML parser for configuration formats; select and document the YAML crate after checking maintenance, advisories, and licenses (`serde_yaml` is unmaintained and must not be selected);
- Clap for command-line parsing;
- `tracing` and `tracing-subscriber` for structured logging;
- `prometheus-client` for metrics;
- `rust-embed` or `include_dir` for embedded UI assets;
- small dependency-free browser JavaScript using `fetch` for API access;
- AWS SDK for S3-compatible object storage, configured to use Rustls;
- `ipnet` for CIDR parsing and membership checks;
- `sha2` for artifact checksums and fixed-length token digests, with a dedicated constant-time comparison implementation such as `subtle` for token verification; hashing alone is not constant-time comparison.

Keep dependencies small and prefer mature crates with compatible permissive licenses.

## 3. Project layout

Create the following initial layout:

```text
galaxyd/
├── Cargo.toml
├── Cargo.lock
├── LICENSE
├── README.md
├── PLAN.md
├── justfile
├── deny.toml
├── Containerfile
├── config/
│   ├── galaxyd.example.toml
│   └── galaxyd.example.yaml
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── runtime.rs
│   ├── reload.rs
│   ├── auth.rs
│   ├── client_ip.rs
│   ├── api/
│   ├── galaxy/
│   ├── storage/
│   ├── health/
│   ├── metrics/
│   └── ui/
├── static/
└── tests/
```

## 4. Configuration

Implement a typed configuration model that can be deserialized from either TOML or YAML. Detect the format from the file extension; reject unsupported extensions with a clear error.

The CLI must support:

```text
galaxyd --config /path/to/config.toml
```

The default path must be:

```text
/etc/galaxyd/galaxyd.toml
```

The configuration should cover:

- an explicit `public_url` including scheme, external host, and optional deployment path prefix; derive API, pagination, task, and download links from this value rather than untrusted Host or forwarding headers;
- public API/UI listener address;
- separate observability listener address;
- storage backend and backend-specific settings;
- namespaces;
- token directory, defaulting to `/etc/galaxyd/tokens`;
- trusted proxy networks for forwarded-client-IP handling;
- logging and UI settings.

Example shape:

```toml
[server]
public_url = "https://galaxy.example.org"
listen = "0.0.0.0:8080"
observability_listen = "0.0.0.0:9090"

[storage]
type = "local"
path = "/var/lib/galaxyd"

# For S3, use type = "s3" and configure endpoint, bucket, region, and prefix.

[network]
# Equivalent in purpose to nginx set_real_ip_from.
set_real_ip_from = ["127.0.0.1/32", "10.0.0.0/8"]

[[namespaces]]
name = "engineering"
push_networks = ["10.20.0.0/16"]

[[namespaces]]
name = "platform"
# Empty or omitted push_networks means any source IP may publish,
# subject to token authentication.
```

Validate the full configuration before starting or applying a reload. Validate namespace names, duplicate namespaces, listener addresses, storage settings, CIDRs, and conflicting settings. Reject unknown fields. Support `.toml`, `.yaml`, and `.yml`. Provide `galaxyd --check-config` for offline syntax and semantic validation without opening listeners.

The product name is `galaxyd`; the version comes from build metadata (`CARGO_PKG_VERSION`), not operator configuration. Storage settings must include local staging space even for S3, bounded upload/concurrency limits, S3 endpoint/region/bucket/prefix/path-style options, and credential-provider selection. Credential material is supplied by mounted secrets or a documented AWS credential provider; behavior configuration remains file-based.

## 5. Storage abstraction

Define a storage trait that supports:

- storing an immutable collection artifact;
- reading an artifact by namespace (= namespace), collection, and version;
- listing namespaces, collections, and versions;
- checking whether a version already exists;
- atomic or crash-safe publication semantics;
- storage health checks.

Implement two backends:

### Local directory

Use deterministic paths below the configured root. Do not derive paths directly from unchecked request strings. Validate and normalize all namespace, namespace, collection, and version components before constructing paths.

Use an immutable publication record as the visibility boundary. Write and fsync a uniquely named artifact, then create the final record atomically with no replacement (for example, an atomic hard-link installation of a fully written record on the same filesystem). Sync containing directories for durability. A check followed by ordinary rename is insufficient: the commit primitive must reject an existing record atomically. Reject duplicate versions with HTTP 409, even if their bytes match.

### S3-compatible bucket

Use the same logical publication-record model as local storage. Upload each artifact under a unique immutable object key and complete multipart upload before publishing its record. Create the version's record with conditional `PutObject` (`If-None-Match: *`). Never use an existence check followed by unconditional copy/write as the commit algorithm. A losing concurrent writer returns 409 and leaves its artifact eligible for cleanup. Verify the referenced object's size and SHA-256; S3 ETags are not artifact SHA-256 values.

Require the chosen S3-compatible service to support the necessary conditional writes and consistency semantics; verify these in integration tests and reject unsupported backends. Do not silently weaken immutability.

Support standard AWS credential resolution and an optional custom S3 endpoint for MinIO and other S3-compatible services. Do not place credentials in the example configuration.

### Catalog, recovery, and process model

Versioned JSON publication records contain namespace, name, version, collection metadata, dependencies, artifact key, byte size, SHA-256, publication timestamp, and import-task identity. A record referencing a complete artifact is the source of truth. The configured namespace list is authoritative, including empty namespaces. Records for removed namespaces remain stored but are not publicly listed or served.

Build an in-memory search/listing index from committed records at startup; do not become ready until reconstruction completes. Update it after a successful commit and recover it from records after a crash. An indexing failure after commit must trigger recovery rather than roll back or overwrite published data. Define deterministic pagination, namespace/name search, and semantic version ordering, including prereleases.

Release 1 supports one active galaxyd process per storage root or bucket prefix. Use an exclusive local process lock for local storage; document the single-replica constraint for S3 deployments. Conditional storage commits remain mandatory even with this constraint. Multi-replica index synchronization is out of scope.

Add startup reconciliation for interrupted imports, missing artifacts, abandoned staging files, and incomplete multipart uploads. Quarantine invalid records and expose a readiness failure rather than serving corrupt downloads. Cleanup must only remove unreferenced objects older than a documented grace period and must never race active uploads. Include crash-injection tests around every publication boundary and concurrent same-version uploads with exactly one winner.

## 6. Galaxy API compatibility

Implement the API paths needed by `ansible-galaxy` collection publishing and installation, under the configured Galaxy API root, with `/api/galaxy/` as the default public prefix.

The API layer should include:

- collection discovery/listing;
- namespace/namespace listing;
- collection version listing;
- collection metadata;
- artifact download;
- collection upload/publish;
- appropriate 4xx responses for invalid metadata, duplicate versions, unauthorized requests, and forbidden source networks.

### Domain and protocol contract

A namespace is exactly one Ansible collection namespace. Use `(namespace, name, version)` as the unique publication key. The standard upload URL has no namespace component: resolve the target from `MANIFEST.json`, never from the filename, token identity, or a search through all secrets files.

Before implementing handlers, freeze an endpoint/schema contract against pinned supported `ansible-core` releases and record the exact versions in CI. At minimum, cover:

| Endpoint relative to `/api/galaxy/` | Contract |
| --- | --- |
| `GET /` | Discovery with `available_versions` advertising `v3/`. |
| `POST v3/artifacts/collections/` | Multipart `file` and `sha256`; return a JSON `task` URL accepted by the client. |
| `GET v3/imports/collections/{task_id}/` | Namespace-authorized task status with `state`, `started_at`, `finished_at`, `messages`, and failure `error.code`/`error.description`. |
| `GET v3/collections/{namespace}/{name}/` | Client-compatible collection metadata, identifiers, timestamps, and version links. |
| `GET v3/collections/{namespace}/{name}/versions/` | Stable paginated versions with client-compatible `data` and `links.next`. |
| `GET v3/collections/{namespace}/{name}/versions/{version}/` | Namespace/name/version, `download_url`, artifact SHA-256/size, metadata dependencies, and applicable compatibility fields such as `requires_ansible`; explicitly represent unsigned collections. |
| `GET v3/artifacts/{namespace}/{name}/{version}/` | Stream the exact validated artifact bytes with length and checksum metadata. |
| `GET v3/namespaces/` and `GET v3/collections/` | Public RO catalog/search extensions, also consumed by the UI; document filters and bounded pagination. |

Document complete request/response schemas and error envelopes, not only this minimum table. Verify all fields, links, trailing slashes, multipart parsing, pagination, dependency resolution, prerelease handling, and import polling against the pinned clients. Return 401 for missing/invalid credentials, 403 for denied source networks, 409 for duplicate versions, 413 for size limits, and appropriate structured validation errors. Reject ambiguous duplicate authorization headers.

Persist import-task records in the selected storage backend. After bounded staging and namespace authorization, create a task, return HTTP 202 with its URL, and process validation/publication using a bounded worker queue. Successful tasks have `state=completed` and `finished_at`; failed tasks have `state=failed`, `finished_at`, and a useful sanitized error. Authorize polling against the task's stored namespace. On restart, reconcile tasks against committed publication records: mark committed tasks completed and interrupted uncommitted tasks failed. Define retention so recently returned task URLs survive restarts and remain available long enough for client polling.

Reject an already committed duplicate before task acceptance with HTTP 409. A duplicate race discovered after HTTP 202 is reported as a failed task with a conflict error code; exactly one task may publish successfully. Retain credentials needed for the final authorization check only in bounded process memory, never in persisted tasks, and discard them when processing ends.

### Archive validation

Stream uploads to bounded staging storage. Bound compressed bytes, total decompressed bytes, individual entry size, metadata size, entry count, processing time, and concurrent uploads. Locate and parse exactly one `MANIFEST.json` using bounded archive inspection, then authorize its configured namespace before creating an import task or publishing anything. Account for this limited unauthenticated work with request/concurrency limits.

Validate `MANIFEST.json`, `FILES.json`, names, semantic versions, dependencies, the multipart SHA-256, and declared internal checksums. Reject absolute/traversal paths, duplicate normalized paths or manifests, symlinks/hardlinks, special files, and malformed/truncated archives. Inspect archives without extracting entries into the host filesystem. Clean up staging data on errors, cancellation, and restart. Test archives produced by the pinned Ansible clients to ensure these checks accept normal collections.

Do not expose storage implementation details through API responses.

Run actual `ansible-galaxy collection build`, `publish` (including polling), and `install` in CI for each pinned supported client version and both backends. Include dependency resolution, multiple pages, download checksum verification, and negative authorization tests; HTTP fixtures supplement rather than replace these end-to-end tests.

## 7. Namespace authentication and authorization

For namespace `NAME`, read tokens from:

```text
/etc/galaxyd/tokens/NAME.secrets
```

The token file format is one token per line. Ignore blank lines and comments beginning with `#`; trim surrounding whitespace; reject unsafe file permissions where practical and document the required ownership/mode.

For an upload:

1. Require exactly one supported authorization header and resolve the effective client IP.
2. Resolve the target namespace from bounded `MANIFEST.json` inspection and load only that configured namespace's secrets file.
3. Accept `Authorization: Token <secret>` (standard Galaxy client) and `Authorization: Bearer <secret>` as equivalent schemes; never accept credentials from query parameters.
4. Compare it against the target namespace's token set.
5. Resolve the effective client IP.
6. Check the namespace's `push_networks`.
7. Validate and publish the collection.

Never authorize a namespace by searching all token files. A token present only in namespace A must not authorize a publish to namespace B. A token explicitly present in both files is intentionally valid for both namespaces.

For release 1, read the small, size-bounded secrets file fresh at each authorization decision, including task polling and the final publication authorization check. Do not use an mtime-only cache. Replace token files atomically during rotation; an already opened file is a consistent snapshot for that decision, and the next decision observes the replacement. Adding a new token preserves old tokens until removed; empty, missing, unreadable, or invalid files deny publishing for that namespace without falling back to old credentials. SIGHUP also validates/reloads all configured token files. Document restrictive ownership/permissions and support read-only secret mounts owned by the service or its designated group.

Compare fixed-length token digests using a constant-time primitive across the complete namespace's token set. Avoid logging token values, token digests, or authorization headers. Sanitize S3 credentials and signed query strings from errors and logs as well.

Read-only operations should not require a namespace upload token unless a future configuration explicitly enables private read access.

## 8. Client IP and `set_real_ip_from` behavior

Implement an explicit trusted-proxy model equivalent in purpose to nginx `set_real_ip_from`.

Configuration field:

```toml
[network]
set_real_ip_from = ["127.0.0.1/32", "10.0.0.0/8"]
```

Rules:

- By default, use the direct TCP peer address.
- Only trust `X-Forwarded-For` when the direct peer address belongs to one of the configured `set_real_ip_from` networks.
- Use recursive resolution equivalent to nginx `real_ip_recursive on`: starting at the trusted peer, walk right to left while the current hop is trusted; stop at the first untrusted address. If all addresses are trusted, use the leftmost address. Document that nginx defaults to recursive mode off, while galaxyd deliberately uses recursive mode on.
- Strictly validate the entire bounded chain; never skip malformed addresses. Support documented IPv4/IPv6 literal syntax and optional ports, normalize IPv4-mapped IPv6 before CIDR matching, and reject ambiguous duplicate header fields. Bound header bytes and hop count.
- For a trusted peer, missing, empty, malformed, or oversized `X-Forwarded-For` makes the effective client identity invalid: reject publishing with HTTP 400, even when push CIDRs are unrestricted. Never substitute the proxy address for an invalid client identity. Public RO requests may proceed without a resolved client identity, marked explicitly in logs.
- Never allow an untrusted client to choose its own effective IP by sending `X-Forwarded-For`.
- Use the effective client IP for `push_networks` checks and expose both peer and effective IP in structured audit logs without leaking credentials.

Cover direct clients, one/multiple proxies, absent/empty/malformed/duplicate headers, all-trusted chains, spoofed leftmost entries, IPv4/IPv6/mapped addresses, ports, overlapping CIDRs, and hop limits. Include the regression case where the proxy belongs to `push_networks` but the real client does not. Examples must use narrowly scoped actual proxy networks and configure nginx to emit the forwarding header consistently.

## 9. Listeners and HTTP middleware

The public listener serves the Galaxy API and embedded UI. The separate observability listener serves only:

- `/metrics`;
- `/healthz`;
- `/readyz`.

Add a `Server` response header on both listeners, including errors, containing the product name and actual build version, for example:

```text
Server: galaxyd/0.1.0
```

Do not trust externally supplied `Server` headers. Add request IDs, bounded request body sizes, timeouts, structured error responses, and upload size limits.

## 10. Health, readiness, and metrics

`/healthz` should indicate that the process and HTTP server are alive.

`/readyz` should verify that:

- configuration was loaded successfully;
- the configured storage backend is usable;
- required token directory checks have passed, where applicable.

Expose Prometheus metrics for request counts, latency, status codes, upload/download counts, rejected authorization attempts, storage errors, reload successes/failures, and readiness state. Never use raw tokens, full authorization headers, or unbounded user-controlled values as metric labels.

## 11. SIGHUP reload

Install a Unix `SIGHUP` handler.

On reload:

1. Read the configured file again.
2. Parse according to its format.
3. Validate the complete candidate configuration.
4. Construct or validate dependent components.
5. Atomically replace the active runtime configuration only after all checks succeed.

If parsing or validation fails, retain the previous configuration and record a reload failure. Token-file changes apply independently through fresh reads at authorization decisions; a rejected configuration reload must not restore removed tokens.

Apply the following explicit policy:

| Setting | SIGHUP behavior |
| --- | --- |
| Namespaces, push CIDRs, trusted proxies, limits, log filter, UI enablement | Atomically replace after validation. |
| Token files | Re-read independently for each authorization; force validation on reload. |
| Public and observability listener addresses | Bind all new sockets before commit, retain unchanged sockets, then drain replaced listeners. Any bind failure rejects the whole candidate. Address swaps/conflicts requiring old sockets to close first require restart. |
| Storage backend/root/bucket/prefix/endpoint/region/credential-provider configuration and staging directory | Restart required; reject the whole candidate with a clear diagnostic. No implicit migration or partial application. |
| `public_url` and token directory | Restart required, preserving already issued URLs and credential-path semantics. |
| Product/version | Build-time constants; not configurable. |

Each request holds an immutable runtime snapshot for routing, limits, and its storage handle. Before committing an upload, recheck the current namespace, current secrets, and current source-IP policy using the captured peer and raw forwarding header; a namespace removal, token revocation, or CIDR/proxy change can therefore deny an in-flight upload. Serialize this final check and commit against reload activation to define their ordering. External token-file replacement takes effect at the next authorization read and cannot retroactively revoke an already committed operation.

Removed namespaces disappear from new read requests without deleting stored data; existing downloads may complete. Bound draining and gracefully handle SIGTERM/SIGINT, stopping new work and leaving durable task states recoverable. Test bad reloads, simultaneous uploads, policy revocation, namespace removal, listener rollback, and restart-required changes.

## 12. Embedded web UI

Embed HTML, CSS, and small JavaScript assets into the executable. Use browser `fetch` against the public RO JSON endpoints documented in section 6. No separate frontend service, server-side UI data endpoints, or browser build framework is required. Prefer this approach over HTMX here because the same JSON API must serve both UI and external consumers.

The UI must display:

- namespaces;
- collections within each namespace;
- available versions;
- collection metadata and download links;
- search results across namespaces and collections.

The UI must actually consume the public RO API over HTTP, rather than only share internal services. Implement debounced namespace/name search, pagination, empty/error/loading states, and version details. Render untrusted strings with safe DOM text operations, avoid raw HTML insertion, set an appropriate CSP, and bundle assets locally without CDN dependencies. Never request or persist upload tokens in the UI.

Add browser tests for namespace listing, collection listing, version display, empty results, API errors, search filtering, pagination, and malicious metadata. Verify browser network requests use only the documented public RO API for catalog data.

## 13. Testing strategy

Provide unit, integration, and end-to-end tests covering:

- TOML and YAML parsing;
- default config path and CLI behavior;
- validation failures;
- local storage;
- S3 storage using a local S3-compatible test service or mock;
- archive metadata validation;
- immutable versions and duplicate uploads;
- token loading, comments, blank lines, and rotation;
- namespace isolation;
- shared token behavior only when explicitly configured in both namespaces;
- CIDR restrictions;
- trusted-proxy and `X-Forwarded-For` resolution;
- public API and Ansible-compatible upload/download flows;
- UI handlers;
- health and readiness;
- metrics;
- `SIGHUP` success and failure behavior;
- malformed requests, oversized uploads, and storage failures.

Required regression suites additionally cover both auth schemes, token-file deletion/replacement/permission failures, revocation before commit, malformed forwarding headers with an allowlisted proxy, bounded archive inspection and decompression, duplicate manifests/checksum mismatches, concurrent publication with exactly one winner, crash recovery, catalog rebuild, import polling after restart, dependency installation through real clients, actual browser API use, and listener rollback. Use a real S3-compatible service with conditional-write tests; mocks alone are insufficient. Validate scratch startup, the built-in healthcheck, and HTTPS S3 access with the runtime CA configuration.

Run formatting, linting, unit tests, integration tests, and dependency checks from `justfile` and CI.

## 14. Justfile commands

Provide at least:

```text
just fmt
just check
just test
just test-integration
just test-e2e
just test-ui
just lint
just license-check
just build
just container-build
just container-run
```

Use Podman for local container builds and runs. Keep commands reproducible and fail on warnings where practical.

## 15. Container image

Create a multi-stage `Containerfile`:

1. Builder stage compiles a static musl binary.
2. Runtime stage is `scratch`.
3. Copy the `galaxyd` binary, CA certificates, and any required embedded/runtime files.
4. Set a non-root numeric `USER`.
5. Expose the public and observability ports.
6. Provide a bounded-time `galaxyd healthcheck --url http://127.0.0.1:9090/healthz` subcommand and invoke it with exec-form HEALTHCHECK; no shell, curl, or wget is available in scratch. Set the URL to match the deployed observability listener.

TLS termination is outside the container, but CA certificates remain necessary for HTTPS S3 endpoints. Document required mounted paths for configuration, token files, and local storage.

Explicitly configure the TLS client to use the shipped CA bundle (and documented custom CA mounts). Provide writable bounded staging space for both backends, support a read-only root filesystem with explicit writable mounts, and test graceful termination as PID 1. Pin the Rust toolchain and builder image, build with the lockfile, and document supported architectures.

## 16. License and dependency policy

Add the MIT license text in `LICENSE`.

Add `deny.toml` and use `cargo-deny` to check:

- advisories;
- bans;
- licenses;
- sources.

Explicitly allow compatible permissive licenses such as MIT, Apache-2.0, BSD variants, ISC, and Unicode-DFS-2015 as required by selected dependencies. Reject GPL/AGPL and other licenses that are not approved for this project unless the policy is deliberately changed and documented.

Run dependency checks in local `just` commands and CI before container builds.

Set package metadata to `license = "MIT"`. Audit the actual locked dependency graph and selected features before accepting a crate; the existing MIT LICENSE is not evidence that future dependencies have been checked. Record SPDX expressions and any approved exceptions. Inventory bundled JavaScript, CSS, fonts, icons, and other assets separately because cargo-deny does not inspect them. Produce `THIRD_PARTY_NOTICES` and preserve required license/NOTICE texts in distribution artifacts and the image. The project's own code remains MIT; third-party components retain their respective licenses and obligations. Keep Ansible CLI as an external interoperability test tool, and implement the protocol without copying its implementation into the Rust project.

## 17. Documentation

Write `README.md` with:

- build and test instructions;
- Podman usage;
- configuration reference;
- TOML and YAML examples;
- token file format and rotation procedure;
- `set_real_ip_from` security behavior;
- storage setup for local disk and S3;
- nginx reverse-proxy example;
- Ansible client configuration and publish/install examples;
- health, readiness, metrics, and signal handling;
- backup and immutable-version considerations.

Also document the exact supported Ansible client versions, endpoint schemas, one-process storage constraint, record format/recovery, task retention, resource limits, restart-required settings, non-migrating storage changes, and token replacement/revocation semantics.

## 18. Suggested implementation order

1. Bootstrap the Rust project, MIT license, `justfile`, `deny.toml`, and CI checks.
2. Implement typed configuration, TOML/YAML parsing, validation, and CLI defaults.
3. Implement the storage trait and local backend.
4. Implement collection metadata parsing and immutable artifact publication.
5. Implement namespace token authentication and CIDR authorization.
6. Implement trusted-proxy client-IP resolution and its tests.
7. Implement the Galaxy-compatible read-only and upload/download endpoints.
8. Add the S3 backend and storage integration tests.
9. Add listeners, health, readiness, metrics, and `Server` header middleware.
10. Add `SIGHUP` reload and failure-safe runtime replacement.
11. Add embedded HTML/CSS/JavaScript UI consuming the public read-only API.
12. Add the scratch Podman image and operational documentation.
13. Run the complete test, lint, dependency, asset-license, real-client interoperability, browser, recovery, and container verification suite.

Before step 3, freeze the namespace model, protocol schemas, publication-record format, supported client matrix, and restart/reload boundaries described above; these are prerequisites for implementation rather than decisions to defer to individual handlers.

## 19. Acceptance criteria

The implementation is complete when:

- `ansible-galaxy` can publish and install a valid collection through the documented API endpoint;
- local and S3 storage both pass the same behavior tests;
- a token from namespace A cannot publish to namespace B unless explicitly present in B's secrets file;
- token rotation works without process restart;
- namespace push CIDRs are enforced;
- `X-Forwarded-For` is honored only through configured trusted proxy networks;
- `/healthz`, `/readyz`, and `/metrics` are available on the separate listener;
- `Server` identifies galaxyd and its actual build version;
- valid configuration changes apply after `SIGHUP`, while invalid changes leave the previous runtime intact;
- the UI displays and searches namespaces, collections, and versions without a separate frontend service;
- tests cover the security boundaries and storage behavior;
- `cargo deny` passes the dependency policy;
- the application runs from the Podman-built `scratch` image as a non-root user;
- the repository contains the MIT `LICENSE` file and operational documentation.

Additional completion gates:

- standard `Token` and optional `Bearer` credentials both work, with namespace isolation and revoked/missing-file failures tested;
- every pinned supported Ansible client completes build, publish, task polling, dependency resolution, and install against both backends;
- malformed forwarding information never falls back to an allowlisted proxy for publishing;
- concurrent duplicate publication has exactly one winner and no overwritten artifact;
- catalog and import-task state recover after injected crashes without exposing incomplete versions;
- the UI's catalog requests use the documented public RO API;
- restart-required reloads reject the whole candidate, and in-flight upload authorization follows the documented final-check semantics;
- archive/resource limits and runtime scratch healthcheck/HTTPS behavior are verified;
- third-party asset/dependency notices are included and checked.

## 20. Protocol and dependency references

- [Ansible Galaxy API client](https://github.com/ansible/ansible/blob/devel/lib/ansible/galaxy/api.py): discovery, multipart publishing, task polling, metadata, and pagination. Pin release references in the implemented compatibility tests rather than depending on the moving development branch.
- [Ansible authentication headers](https://github.com/ansible/ansible/blob/devel/lib/ansible/galaxy/token.py): Galaxy `Token` and OAuth-style `Bearer` schemes.
- [nginx real IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html): trusted peers and recursive resolution; galaxyd's strict invalid-header publishing policy is deliberate and separately documented.
- [serde_yaml maintenance status](https://docs.rs/serde_yaml/latest/serde_yaml/): rationale for selecting a maintained alternative.
