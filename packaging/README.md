# Service packaging

The repository provides two systemd deployment options:

- `quadlet/galaxyd.container` runs the published amd64 image from GHCR with Podman.
- `systemd/galaxyd.service` runs an installed `galaxyd` release binary directly.

## Quadlet / Podman

Install the unit for a system service:

```sh
sudo install -D -m 0644 packaging/quadlet/galaxyd.container \
  /etc/containers/systemd/galaxyd.container
sudo install -d -m 0750 /etc/galaxyd /var/lib/galaxyd
sudo install -d -o 65532 -g 65532 -m 0700 /etc/galaxyd/tokens
sudo install -m 0640 config/galaxyd.auth.local.example.toml /etc/galaxyd/galaxyd.toml
sudo chown -R 65532:65532 /etc/galaxyd /var/lib/galaxyd
```

Create `/etc/galaxyd/admins.users` with an administrator password hash before
starting the service:

```sh
read -rsp 'Admin password: ' ADMIN_PASSWORD; printf '\n'
ADMIN_HASH="$(printf '%s' "$ADMIN_PASSWORD" | galaxyd password-hash)"
unset ADMIN_PASSWORD
printf 'admin:%s\n' "$ADMIN_HASH" \
  | sudo sh -c 'umask 077; cat > /etc/galaxyd/admins.users'
sudo chown 65532:65532 /etc/galaxyd/admins.users
sudo systemctl daemon-reload
sudo systemctl enable --now galaxyd.service
```

The configuration must use `/var/lib/galaxyd` for local storage and reference
secrets below `/etc/galaxyd`. Inside the container, set `observability_listen`
to `0.0.0.0:9090`; Quadlet binds that port to host loopback only. The API is
published on port `8080`. The Quadlet runs as UID 65532, so the mounted
configuration, secrets, token directory, and data directory must be owned by
that UID; keep secret files mode `0600` and the token directory mode `0700`.

## Native systemd service

Install the amd64 release binary as `/usr/local/bin/galaxyd`, then install the
unit and configuration:

```sh
sudo install -D -m 0755 galaxyd /usr/local/bin/galaxyd
sudo install -D -m 0644 packaging/systemd/galaxyd.service \
  /etc/systemd/system/galaxyd.service
sudo groupadd --system galaxyd
sudo useradd --system --gid galaxyd --home-dir /nonexistent \
  --shell /usr/sbin/nologin galaxyd
sudo install -d -o root -g galaxyd -m 0750 /etc/galaxyd
sudo install -d -o root -g galaxyd -m 0750 /etc/galaxyd/tokens
sudo install -o root -g galaxyd -m 0640 \
  config/galaxyd.auth.local.example.toml /etc/galaxyd/galaxyd.toml
```

Create `/etc/galaxyd/admins.users` with an administrator password hash using
the instructions above:

```sh
read -rsp 'Admin password: ' ADMIN_PASSWORD; printf '\n'
ADMIN_HASH="$(printf '%s' "$ADMIN_PASSWORD" | galaxyd password-hash)"
unset ADMIN_PASSWORD
printf 'admin:%s\n' "$ADMIN_HASH" \
  | sudo sh -c 'umask 027; cat > /etc/galaxyd/admins.users'
sudo chown root:galaxyd /etc/galaxyd/admins.users
sudo chmod 0640 /etc/galaxyd/admins.users
sudo systemctl daemon-reload
sudo systemctl enable --now galaxyd.service
```

The native unit creates `/var/lib/galaxyd` using `StateDirectory` and runs as
the dedicated unprivileged `galaxyd` system user. Token files can remain
root-owned and readable by the `galaxyd` group; keep their directory
non-writable by the service and each file mode `0640`.
