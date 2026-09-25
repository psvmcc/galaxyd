# galaxyd configuration reference

The configuration file is parsed at startup and on SIGHUP. Supported extensions are .toml, .yaml, and .yml. Unknown fields are rejected. The default path is:

~~~text
/etc/galaxyd/galaxyd.toml
~~~

Validate a file without starting listeners:

~~~bash
galaxyd check-config --config ./config.yaml
~~~

## Complete TOML example

~~~toml
token_dir = "/etc/galaxyd/tokens"

[auth]
enabled = false
session_ttl_seconds = 28800

[auth.local]
enabled = false
users_file = "/etc/galaxyd/admins.users"

[auth.oidc]
enabled = false
debug = false
request_offline_access = true
refresh_interval_seconds = 300
issuer_url = "https://login.example.org/realms/company"
client_id = "galaxyd"
client_secret_file = "/etc/galaxyd/oidc-client.secret"
display_name = "Company SSO"
groups_claim = "groups"

[[auth.oidc.group_mappings]]
group = "galaxy-administrators"
admin = true

[[auth.oidc.group_mappings]]
group = "galaxy-engineering"
namespaces = ["engineering"]

[server]
listen = "0.0.0.0:8080"
observability_listen = "127.0.0.1:9090"
public_url = "https://galaxy.example.org"
ui_enabled = true

[storage]
type = "local"
path = "/var/lib/galaxyd"

# S3 alternative:
# type = "s3"
# bucket = "galaxyd"
# prefix = "collections"
# endpoint = "https://s3.example.org"
# region = "us-east-1"
# force_path_style = false

[network]
set_real_ip_from = [] # Configure only the exact addresses of trusted reverse proxies.
max_upload_bytes = 134217728
max_forwarded_for_hops = 16

[[namespaces]]
name = "engineering"
push_networks = ["10.20.0.0/16"]

[[namespaces]]
name = "platform"
push_networks = []
~~~

## Complete YAML example

~~~yaml
server:
  listen: 0.0.0.0:8080
  observability_listen: 127.0.0.1:9090
  public_url: https://galaxy.example.org
  ui_enabled: true

storage:
  type: local
  path: /var/lib/galaxyd

network:
  set_real_ip_from: [] # Configure only exact trusted reverse-proxy addresses.
  max_upload_bytes: 134217728
  max_forwarded_for_hops: 16

token_dir: /etc/galaxyd/tokens

namespaces:
  - name: engineering
    push_networks:
      - 10.20.0.0/16
  - name: platform
    push_networks: []
~~~

## server

- listen: socket address, default 0.0.0.0:8080. Public API and UI listener.
- observability_listen: socket address, default 127.0.0.1:9090. Health and metrics listener. Must differ from listen.
- public_url: string, default http://localhost:8080. External URL for public links; no trailing slash.
- ui_enabled: boolean, default true. When false, / is disabled.

The product name is galaxyd and the version comes from the binary build. They are not configuration options.

## storage

type is local or s3.

### local

- path: filesystem path, required. The process needs read/write access. The backend creates records and artifacts below this path.

### s3

- bucket: required bucket name.
- prefix: optional object-key prefix, default empty.
- endpoint: optional custom S3-compatible endpoint.
- region: optional AWS region.
- force_path_style: boolean, default false.

S3 credentials are not stored in the configuration. Standard AWS SDK credential resolution is used, including environment variables and mounted credential files.

## network

- set_real_ip_from: list of trusted proxy CIDRs, default empty. X-Forwarded-For is honored only from a direct peer in these networks.
- max_upload_bytes: positive integer, default 134217728 (128 MiB).
- max_forwarded_for_hops: positive integer, default 16.

A malformed, empty, missing, duplicated, or oversized forwarding header from a trusted proxy rejects a publishing request.

## token_dir

Path to namespace token files. Default:

~~~text
/etc/galaxyd/tokens
~~~

For namespace engineering, the file is <token_dir>/engineering.secrets. Each non-empty, non-comment line is a token. Keep it readable only by the service (mode 0600 when owned by it, or 0640 with a dedicated service group).

The file is read on each authorization decision, so token rotation does not need a restart:

~~~text
old-token
new-token
~~~

Removing the old token revokes it on the next decision. Missing or unreadable files deny publishing.

When global authorization is enabled, machine read access requires a namespace token file. Use:

~~~text
<token_dir>/engineering.read.secrets
<token_dir>/engineering.write.secrets
~~~

An RO token in `.read.secrets` permits metadata, version listing, and artifact download. A write token in `.write.secrets` permits all of those operations and publishing. The legacy `<namespace>.secrets` filename remains a write-token file. A write token is intentionally accepted for read operations. Without a valid RO or write token, Ansible clients receive `401`; local administrators and authorized OIDC users use their browser session instead.

With `auth.enabled = false`, these files do not affect anonymous read access. With `auth.enabled = true`, anonymous users cannot access the catalog or UI. The `/api/galaxy/` discovery response requires a valid session or a read/write token for at least one configured namespace.

Local login and logout require the browser's `Origin` to match `server.public_url` in scheme, hostname, and port. If a browser form returns `403`, check that `public_url` is the address users actually open, including HTTPS and any non-default port. Rejected origins and unavailable local-user files are recorded in server logs without logging passwords.

OIDC `request_offline_access` defaults to `true`. Set it to `false` only when the provider rejects that scope. `refresh_interval_seconds` defaults to 300 and must be shorter than `session_ttl_seconds`. The server checks current groups on the first request after that interval. Without a refresh token, the session ends at that check and the user signs in again. A temporary provider error returns `503` while preserving the session for a later retry; revoked refresh credentials end the session.

The OIDC redirect URI is `server.public_url` plus `/auth/oidc/callback`. Register that full URI in the identity provider. With OIDC enabled, `server.public_url` must use HTTPS, except for HTTP on loopback during development. Remove `auth.oidc.redirect_url` from existing configurations; it is no longer accepted.

Generate a local administrator password hash without putting the password in shell history:

~~~bash
printf '%s\n' 'change-me' | galaxyd password-hash
~~~

Create `/etc/galaxyd/admins.users` with one `username:argon2id PHC hash` entry per line. Local users are global administrators. OIDC users receive namespace access from `group_mappings`; a mapping with `admin = true` grants all namespaces. The OIDC client secret is read from its separate file. Keep both files readable only by the service (mode 0600 when owned by it, or 0640 with a dedicated service group). Restrict their containing directory to the service and administrator accounts.

OIDC discovery, JWKS, token, and UserInfo responses have strict size limits and timeouts. Provider endpoints must use HTTPS; HTTP is accepted only for loopback development endpoints. URLs cannot contain embedded credentials or fragments.

## namespaces

Each namespace entry contains:

- name: required unique collection namespace. ASCII letters, digits, _, -, and .; maximum 128 characters.
- push_networks: optional CIDR list. Empty or omitted means all source addresses are allowed after token authentication.

The upload namespace comes from MANIFEST.json and must match a configured namespace.
`max_upload_bytes` limits the decoded collection archive. Multipart uploads using base64 may use more bytes on the wire; the server separately limits the encoded request body. Archives with PAX size overrides or oversized TAR extension records are rejected.

## Reload

Send SIGHUP:

~~~bash
kill -HUP $(pgrep galaxyd)
~~~

A valid configuration replaces the active configuration. Invalid configuration leaves the previous configuration active. Namespaces, CIDRs, trusted proxies, forwarding limits, and UI enablement are reloaded. Listener addresses, `public_url`, storage, `token_dir`, and `max_upload_bytes` require a restart; changing one of them rejects the complete reload. Token files are independent and are read on every authorization decision.

An upload is authorized again immediately before its immutable publication record is committed. Namespace removal, token revocation, and proxy or source-network policy changes therefore apply to uploads that were already being inspected when a reload occurred.

## Environment variables

- RUST_LOG=debug changes tracing verbosity.
- AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN may configure S3 access through the AWS SDK.

Do not place tokens or S3 secret keys in the configuration file or command line.
