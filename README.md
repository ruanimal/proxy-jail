# Proxy Jail

Force GUI applications through SOCKS5 proxy using Linux network namespaces and tun2socks.

## Overview

Proxy Jail creates isolated network environments for your applications using Linux network namespaces. All traffic from the jailed application is transparently routed through a SOCKS5 proxy, providing:

- **Complete traffic isolation** - All TCP/UDP/DNS traffic goes through the proxy
- **No root required** - Uses file capabilities instead of sudo, config stored in user directories
- **Transparent to applications** - Apps work normally without configuration
- **Desktop integration** - Generates .desktop files for seamless launching

## Architecture

```
GUI App ──► TUN (tun2socks) ──► SOCKS5 ──► Internet
  (netns: pj-work)
```

Each jail consists of:
- **Network Namespace** (`pj-{name}`) - Isolated network stack
- **veth pair** - Connects namespace to host
- **tun2socks** - Converts all IP traffic to SOCKS5
- **iptables NAT** - Routes traffic from namespace to host

## Requirements

- Linux with kernel support for:
  - `CONFIG_NET_NS=y`
  - `CONFIG_TUN=y`
  - `CONFIG_VETH=y`
- `iproute2` (provides `ip` command)
- `iptables`
- `tun2socks` binary (bundled automatically in `.deb` package)

## Installation

### 1. Build from source

```bash
cargo build --release
```

### 2. Install binary

From source:

```bash
sudo cp target/release/proxy-jail /usr/local/bin/
```

Or build a `.deb` package (recommended; the postinst script will register the
sudoers rule for you, and `tun2socks` is bundled automatically):

```bash
cargo install cargo-deb
scripts/fetch-tun2socks.sh       # downloads tun2socks for current arch
cargo deb --release
sudo dpkg -i target/debian/proxy-jail_*.deb
```

When installing via `.deb`, the `postinst` automatically writes
`/etc/sudoers.d/proxy-jail` so that all users can run `proxy-jail` without a
password prompt. The file is removed on `apt purge` (but kept on `apt remove`).

The `.deb` package also bundles the `tun2socks` binary at
`/usr/lib/proxy-jail/tun2socks`, so no separate installation is needed.

### 3. Configure passwordless sudo (only when installing from source)

When installing the binary manually (without `.deb`), configure a sudoers rule
so you won't be prompted for a password:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/local/bin/proxy-jail" | sudo tee /etc/sudoers.d/proxy-jail
sudo chmod 440 /etc/sudoers.d/proxy-jail
```

> **Note**: Only `proxy-jail` itself is allowed via sudoers. Individual `ip`, `iptables` commands are not exposed — they run internally within proxy-jail after privilege elevation.

You will also need a `tun2socks` binary on your `$PATH`:
```bash
# Download from https://github.com/xjasonlyu/tun2socks/releases/tag/v2.7.0
# and place the binary somewhere in $PATH, e.g.:
sudo cp tun2socks /usr/local/bin/
```

## Usage

### Create a jail

```bash
proxy-jail jail create work --socks5 127.0.0.1:1080
```

### Run an application

```bash
proxy-jail app exec --jail work -- firefox
```

### List jails

```bash
proxy-jail jail list
```

### List running applications

```bash
proxy-jail app list
# or filter to a single jail
proxy-jail app list --jail work
```

### Install desktop entry

```bash
proxy-jail desktop create --jail work --from firefox
```

### Stop a jail

```bash
proxy-jail jail stop work
```

### Delete a jail

```bash
proxy-jail jail delete work
```

## Configuration

Configuration is stored at `~/.config/proxy-jail/config.yaml` (respects `$XDG_CONFIG_HOME`). See `config.example.yaml` for the format.

### Example configuration

```yaml
jails:
  - name: work
    proxy:
      host: "127.0.0.1"
      port: 1080
      type: socks5

```

## How it works

1. **Network namespace creation**: Creates an isolated network stack named `pj-{jail}`
2. **veth pair**: Creates a virtual ethernet pair connecting the namespace to the host
3. **tun2socks**: Starts a TUN device inside the namespace that converts all IP traffic to SOCKS5
4. **Routing**: Sets up routes so all traffic goes through the TUN device
5. **NAT**: Adds iptables MASQUERADE rule on the host to forward traffic
6. **Application launch**: Enters the namespace, drops privileges, and executes the application

## Security considerations

- Privileged operations use sudo with a scoped sudoers rule (no full root access)
- Configuration and runtime files are stored in user directories (`~/.config/proxy-jail/`, `$XDG_RUNTIME_DIR/proxy-jail/`)
- Applications run with dropped privileges (actual user, not root)
- Network isolation is complete - no traffic leaks outside the proxy
- DNS queries are also proxied (no DNS leaks)

## Limitations

- Linux only (requires network namespaces)
- Requires SOCKS5 proxy (no support for other proxy protocols)
- No GUI management interface (CLI only)
- Some applications may not work correctly with network namespace isolation

## Development

### Project structure

```
src/
├── main.rs          # CLI entry point
├── config.rs        # YAML configuration loading
├── jail.rs          # Jail lifecycle management
├── network.rs       # Network namespace operations
├── proxy.rs         # tun2socks configuration and process management
├── launcher.rs      # Application launcher (setns + setuid + exec)
└── desktop.rs       # .desktop file generation
```

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

## License

MIT
