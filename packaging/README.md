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
sudo install -m 0640 config/galaxyd.example.toml /etc/galaxyd/galaxyd.toml
sudo systemctl daemon-reload
sudo systemctl enable --now galaxyd.service
```

The configuration must use `/var/lib/galaxyd` for local storage and reference
secrets below `/etc/galaxyd`. The container publishes ports `8080` and `9090`.

## Native systemd service

Install the amd64 release binary as `/usr/local/bin/galaxyd`, then install the
unit and configuration:

```sh
sudo install -D -m 0755 galaxyd /usr/local/bin/galaxyd
sudo install -D -m 0644 packaging/systemd/galaxyd.service \
  /etc/systemd/system/galaxyd.service
sudo install -d -m 0750 /etc/galaxyd
sudo install -m 0640 config/galaxyd.example.toml /etc/galaxyd/galaxyd.toml
sudo systemctl daemon-reload
sudo systemctl enable --now galaxyd.service
```

The native unit creates `/var/lib/galaxyd` using `StateDirectory` and runs with
a dynamic unprivileged user.
