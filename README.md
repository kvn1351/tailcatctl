# tailcatctl

`tailcatctl` is a fast, lightweight connection manager and CLI tool for [Tailcat](https://github.com/tailcat) endpoints. It mimics the syntax, conventions, and user experience of the **Tailscale CLI** (`tailscale ssh`, `tailscale status`, `tailscale ping`, `tailscale switch`), backed by saved Tailcat and LAN connections and an on-demand background SSH multiplexing broker.

## Features

- **Tailscale-compatible SSH Syntax**:
  - `tailcatctl ssh kindle` — Interactive terminal shell on saved device.
  - `tailcatctl ssh root@kindle uname -a` — Run remote command with piped I/O and exact remote exit status.
  - `tailcatctl ssh user@tc4e3b79...` — Ad-hoc connection to a direct Tailcat address.
  - `tailcatctl ssh kindle:lan` — Explicitly connect over the device's LAN endpoint.
- **Connection Multiplexing Broker**:
  - Automatically manages OpenSSH ControlMaster connections in the background.
  - Multiple applications and CLI commands share a single authenticated connection without reconnect latency.
  - Automatic lease tracking: the background master idles out and cleans up when all client leases are released.
  - Watchdog supervision ensures no orphaned SSH or proxy processes if the broker or client exits unexpectedly.
- **Tailscale-like Device Management**:
  - `tailcatctl status` — Formatted status table of devices, active endpoints, and lease counts.
  - `tailcatctl ping <device>` — Measures latency to the target (TCP probe for LAN, proxy probe for Tailcat).
  - `tailcatctl switch <device>` — Selects default active device (`switch --list` lists devices with active marker).
  - `tailcatctl add` / `tailcatctl remove` — Manage paired LAN and Tailcat endpoints.
- **Secure by Default**:
  - Strict SSH host-key checking against `ssh_known_hosts`.
  - Passwords are **never stored on disk**; credentials use SSH keys/agent or interactive password prompting.
  - Device registry and runtime sockets are stored in restricted user-owned directories (`0700`) with locked atomic updates.

---

## Installation & Build

Requires Rust 1.75+ and OpenSSH (`ssh` / `sftp`):

```bash
cargo build --release
# Binary will be at target/release/tailcatctl
```

To install to your `PATH` (e.g. `~/.cargo/bin` or `/usr/local/bin`):

```bash
cargo install --path .
```

---

## Configuration & Storage Layout

Following standard Unix conventions (and Tailscale's storage structure):

| Item | Location | Environment Override |
| --- | --- | --- |
| **Device Registry** | `~/.config/tailcat/devices.json` | `TAILCATCTL_CONFIG_DIR` |
| **SSH Known Hosts** | `~/.config/tailcat/ssh_known_hosts` | `TAILCATCTL_CONFIG_DIR` |
| **Broker Runtime Socket** | `/tmp/tailcatctl-<uid>/broker.sock` | `TAILCATCTL_RUNTIME_DIR` |

### Device Registry Format

Devices are stored in `~/.config/tailcat/devices.json`:

```json
{
  "version": 1,
  "revision": 1,
  "active_device_id": "dev_kindle",
  "active_endpoint": "tailcat",
  "devices": [
    {
      "id": "dev_kindle",
      "name": "kindle",
      "tailcat": {
        "host": "tc4e3b79f2c7a840e2417e908b",
        "port": 22,
        "username": "root",
        "identity_file": "~/.ssh/id_ed25519",
        "known_hosts": "~/.config/tailcat/ssh_known_hosts"
      },
      "lan": {
        "host": "192.168.1.150",
        "port": 22,
        "username": "root",
        "identity_file": "~/.ssh/id_ed25519",
        "known_hosts": "~/.config/tailcat/ssh_known_hosts"
      },
      "metadata": {}
    }
  ]
}
```

---

## Command Reference

### `tailcatctl ssh [flags] [user@]<device> [command...]`

Starts an interactive shell or executes a remote command on the target:

```bash
# Interactive shell to active device
tailcatctl ssh

# Interactive shell to named device
tailcatctl ssh kindle

# Specific user
tailcatctl ssh root@kindle

# Non-interactive remote command
tailcatctl ssh root@kindle cat /etc/os-release

# Target specific endpoint (lan or tailcat)
tailcatctl ssh root@kindle:lan uname -a
tailcatctl ssh --endpoint tailcat kindle df -h

# Direct Tailcat address without saving to registry
tailcatctl ssh root@tc4e3b79f2c7a840e2417e908b
```

### `tailcatctl status [--json] [--active]`

Displays the current state of devices and connections:

```text
ADDRESS                          DEVICE   USER  ENDPOINT  STATUS
tc4e3b79f2c7a840e2417e908b...    kindle*  root  tailcat   active; direct (1 lease)
192.168.1.150:22                 kindle*  root  lan       idle
```

Pass `--json` for machine-readable JSON output, or `--active` to filter to connected endpoints.

### `tailcatctl ping <device>`

Pings a device or endpoint to check reachability and measure round-trip latency:

```bash
tailcatctl ping kindle
# pong from kindle (tc4e3...) via tailcat in 42.5ms
```

### `tailcatctl switch <device> | switch --list [--json]`

Switches the active default device:

```bash
# List available devices
tailcatctl switch --list

# Switch active device
tailcatctl switch kindle
```

### `tailcatctl add <name> --tailcat <addr> [--lan <ip>] [--user <user>] [--key <file>] [--port <port>]`

Adds or updates a device in the registry:

```bash
tailcatctl add kindle \
  --tailcat tc4e3b79f2c7a840e2417e908b \
  --lan 192.168.1.150 \
  --user root \
  --key ~/.ssh/id_ed25519
```

### `tailcatctl remove <device>`

Removes a device from the registry.

---

## License

MIT OR Apache-2.0
