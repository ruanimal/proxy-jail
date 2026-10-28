# Proxy Jail

Force GUI applications through SOCKS5 proxy using Linux network namespaces and tun2socks.

## Overview

Proxy Jail creates isolated network environments for your applications using Linux network namespaces. All traffic from the jailed application is transparently routed through a SOCKS5 proxy, providing:

- **Complete traffic isolation** - All TCP/UDP/DNS traffic goes through the proxy
- **Restricted sudoers, not rootless** - Runs as root *only* via a single, scoped NOPASSWD rule for the `proxy-jail` binary itself; see [Privilege model](#privilege-model)
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
- For desktop cache refresh: `update-desktop-database` from `desktop-file-utils`
  (recommended by the `.deb`), and the matching `kbuildsycoca6`/`kbuildsycoca5`
  tool when using KDE Plasma.

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

> **Note**: Only `proxy-jail` itself is allowed via sudoers. Individual `ip`, `iptables` commands are not exposed — they run internally within proxy-jail after privilege elevation. See [Privilege model](#privilege-model) for the full security boundary.

You will also need a `tun2socks` binary on your `$PATH`:
```bash
# Download from https://github.com/xjasonlyu/tun2socks/releases/tag/v2.7.0
# and place the binary somewhere in $PATH, e.g.:
sudo cp tun2socks /usr/local/bin/
```

## Usage

### Output and diagnostics

Operation progress, success/no-op messages, and diagnostic logs go to stderr.
Lists go to stdout; `app exec` preserves the application's own stdout, so it
can still be redirected or piped without mixing in proxy-jail messages.

- `jail create` confirms the configuration path, allocated network, and next
  commands. Creation saves the configuration but does not start the jail.
- `jail start` reports whether it started the jail or found it already running,
  plus the namespace, proxy endpoint, subnet, gateway, jail IP, tun2socks PID,
  and log path. Proxy credentials are omitted from these summaries.
- `jail list` includes `SUBNET`, `GATEWAY`, `DNS`, and `DNS SEARCH`. DNS
  columns show configured servers (including public defaults when unset) and
  search suffixes, comma-separated without truncation; `DNS SEARCH` is `-`
  when empty. These values are shown even for stopped jails and do not verify
  runtime DNS health. `NETNS IP` is `-` for a stopped jail; `Partial` means the
  namespace exists but tun2socks is not running and includes a restart hint.
  `Running` does not verify upstream connectivity.
- `app exec` reports the registered application's `APP_ID` and PID on stderr.
  `app stop` confirms that SIGTERM was sent, rather than claiming the process
  has already exited. Stopping or deleting a jail does not terminate its apps;
  relaunch them after recreating the jail network.

Normal feedback does not require `-v`. Add `-v`, `-vv`, or `-vvv` for info,
debug, or trace logs respectively; these options also work after subcommands:

```bash
proxy-jail jail list -v
```

Help, version information, and argument validation work without sudo.

### Create a jail

```bash
proxy-jail jail create work --socks5 127.0.0.1:1080

# Or use a SOCKS5 URI with username and password:
proxy-jail jail create work --socks5 'socks5://user:password@127.0.0.1:1080'
```

Percent-encode reserved characters in credentials (for example, `@` as `%40`
and `:` as `%3A`). Credentials are saved in the configuration file and passed
to `tun2socks` as a process argument; protect access to both. Command-line
arguments may also be saved in your shell history. IPv6 proxy addresses are
not currently supported.

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

Each row shows a stable `APP_ID` (16 hex chars) for the invocation —
this is the only thing `app stop` accepts.  Using a stable per-launch
id (instead of the argv[0] basename) is what makes it safe to run
multiple instances of the same binary in one jail (e.g. two
`python` processes): each gets its own id and stops independently.

### Stop a running application

```bash
# Copy the APP_ID column from `app list`
proxy-jail app stop --jail work 7f3a2b1c9d4e5f60

# A unique prefix is also accepted
proxy-jail app stop --jail work 7f3a2b1c
```

### Install desktop entry

```bash
proxy-jail desktop create --jail work --from firefox
```

Desktop entries are owned by the invoking user. To fix an existing entry
created by an older version as root, run the same `desktop create` command
again for that entry.

After creating or deleting an entry, proxy-jail refreshes the user applications
database with `update-desktop-database`. In KDE sessions it also rebuilds the
application menu cache with `kbuildsycoca6 --noincremental` or the KDE 5
equivalent, matching `KDE_SESSION_VERSION` when available. Cache tools run as
the invoking user with that user's HOME, not as sudo's root account.

Missing tools or refresh failures produce a warning; the completed desktop
file change is kept. Install `desktop-file-utils` if the database tool is
missing. You can retry the refresh manually from your normal desktop session:

```bash
update-desktop-database "$HOME/.local/share/applications"
kbuildsycoca6 --noincremental  # KDE Plasma 6; use kbuildsycoca5 for Plasma 5
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

Automatic allocation uses consecutive `/30` subnets from `10.203.240.0/20`
(for example, `10.203.240.0/30`, then `10.203.240.4/30`). Each has two usable
addresses: network + 1 for the host gateway and network + 2 for the jail.
Only the individual `/30` routes are installed, not a route for the whole pool.
The allocator skips ranges overlapping configured jails or non-default host
IPv4 routes across all routing tables, and reports an error if the pool is full.
No private pool is guaranteed conflict-free when networks change later.

Assignments are saved so they stay stable when other jails are added or
deleted. You can also set `subnet` explicitly; existing explicit subnets,
including legacy `/24` configurations, are kept unchanged. Missing subnets are
assigned and saved on first load. To migrate a running jail, stop it while its
old subnet is still configured, edit `subnet`, then start it again. Applications
left in the old namespace must be relaunched to use the recreated network.

### Example configuration

```yaml
jails:
  - name: work
    proxy:
      host: "gateway"
      port: 1080
      type: socks5
```

> **Note**: Use `host: "gateway"` for proxies listening on localhost.
> Inside the network namespace, `127.0.0.1` would refer to the namespace's
> own loopback, not the host. The `"gateway"` value is automatically
> resolved to the host's veth IP at runtime. If your proxy listens on a
> specific LAN address, use that address directly instead.

### DNS through each jail's proxy

By default, jails use `1.1.1.1` and `8.8.8.8`, not a copy of the physical
network's DNS servers or search domains. Set `dns_servers` per jail to use
internal DNS reachable from **that jail's SOCKS5 exit**:

```yaml
jails:
  - name: work
    proxy:
      host: "gateway"
      port: 1080
    dns_servers: ["10.88.0.53", "10.88.0.54"]
    dns_search: ["corp.example"]
```

The CLI supports the same settings on creation and for existing jails:

```bash
proxy-jail jail create work --socks5 127.0.0.1:1080 \
  --dns 10.88.0.53,10.88.0.54 --dns-search corp.example
proxy-jail jail dns work                           # Show configured DNS
proxy-jail jail dns work --dns 10.88.0.53           # Replace servers only
proxy-jail jail dns work --dns-search corp.example # Replace search suffixes only
proxy-jail jail dns work --reset-dns               # Restore public defaults
proxy-jail jail dns work --clear-dns-search        # Remove search suffixes
```

`--dns` (alias `--dns-server`) and `--dns-search` accept repeated options or
comma-separated values. Omitted settings are preserved on update. Changes
are saved and applied in place when the jail namespace already exists,
without restarting applications or tun2socks; stopped jails use them on the
next start. A failure to apply the saved configuration is reported as an
error, not success. Viewing DNS without update options does not change it.

The example addresses must be replaced with actual internal DNS servers.
Each jail runs an unprivileged DNS relay listening only on its loopback
`127.0.0.1:53` over UDP and TCP. It forwards each query separately over TCP
to the configured upstream via `tun0` and that jail's SOCKS5 proxy, including
upstreams that close TCP connections after a single response. This also lets
UDP DNS clients work with TCP-only SOCKS5 servers. The actual upstream routes
must use `tun0`; bypassed addresses are rejected when starting the relay.
No direct host/VPN DNS exception is added. The proxy must be able to reach
the configured upstream DNS servers; its rules decide the onward path.

Explicit `dns_servers` replace the defaults, rather than appending public
fallbacks. The internal DNS servers should also resolve/forward public names
if the jail needs them: a list of internal and public servers is failover,
not split DNS, and NXDOMAIN does not trigger a retry with a public server.
`dns_search` expands short names such as `git` to `git.corp.example`; it does
not implement domain-based routing. DNS server addresses must be IPv4; an
explicitly empty list is rejected.

The managed `resolv.conf` points to the local relay and includes `options
use-vc` for glibc. Applications that honor the system resolver can use either
local TCP or UDP. Applications with their own DNS or DoH settings may bypass
the relay; Chrome may need its own DNS cache cleared or a restart after a DNS
change. LAN-only DNS names and search domains are not inherited from the host.
The relay does not provide split DNS or a DNS cache.

For an existing jail, run the **updated binary** without stopping it:

```bash
proxy-jail jail start work
```

This starts the relay and refreshes DNS in place, preserving the file inode
bound into running applications; it does not restart tun2socks or applications.
Applications may retain cached DNS settings or results until reloaded or
restarted. Launching another app in the jail also starts or refreshes the
relay. Avoid using an older proxy-jail binary afterward: it may overwrite the
resolver configuration with its legacy direct-upstream settings.

## How it works

1. **Network namespace creation**: Creates an isolated network stack named `pj-{jail}`
2. **veth pair**: Creates a virtual ethernet pair connecting the namespace to the host
3. **tun2socks**: Starts a TUN device inside the namespace that converts all IP traffic to SOCKS5
4. **Routing**: Sets up routes so all traffic goes through the TUN device
5. **NAT**: Adds iptables MASQUERADE rule on the host to forward traffic
6. **Application launch**: Enters the namespace, drops privileges, and executes the application

## Reaching services inside a jail

When you `app exec` a server (e.g. `python -m http.server`), the service
listens on a veth IP *inside* the netns (e.g. `10.203.240.2`). That IP is
reachable from the host — find it in `jail list`:

```text
NAME            PROXY                  STATUS     SUBNET               GATEWAY         NETNS IP        DNS                             DNS SEARCH
work            10.203.240.1:1080      Running    10.203.240.0/30      10.203.240.1    10.203.240.2    1.1.1.1,8.8.8.8                 -
```

proxy-jail does **not** auto-forward ports.  You forward them yourself
with `socat` (or `ssh -L`) so you stay in control of *which* ports are
exposed and *where* on the host they bind.

### From the host (loopback only)

```bash
# Forward host 127.0.0.1:8000 → 10.203.240.2:8000
socat TCP-LISTEN:8000,bind=127.0.0.1,fork,reuseaddr TCP:10.203.240.2:8000
```

### From the LAN (bind on all interfaces)

```bash
socat TCP-LISTEN:8000,bind=0.0.0.0,fork,reuseaddr TCP:10.203.240.2:8000
```

### From a remote host via SSH

```bash
# Run on the *remote* machine — proxies through the host running proxy-jail
ssh -L 8000:10.203.240.2:8000 user@proxy-jail-host
```

### Run a command inside the netns (most direct)

```bash
# Whatever you run here sees the same network as the jailed app
sudo ip netns exec pj-work curl http://localhost:8000
```

### Future: `jail expose` (planned, not implemented yet)

A convenience wrapper around the `socat` invocations above is on the
roadmap:

```bash
# Today:  copy-paste the socat command
# Future:  proxy-jail jail expose --jail work --bind 127.0.0.1:8000 --to 8000
```

The wrapper would just be a thin shortcut — it still spawns `socat`
under the hood, doesn't auto-detect ports, and stays independent of
`app exec` so you can expose a port even when the app is started some
other way.

## Privilege model

proxy-jail is **not rootless**: it requires root to create network namespaces,
veth pairs, and `iptables` NAT rules, and that root is obtained by re-executing
itself through `sudo`. What is *scoped* is the surface area of that root — the
attack surface is the same `proxy-jail` binary, nothing more.

| Aspect | Implementation |
| --- | --- |
| Root acquisition | `proxy-jail` re-execs itself via `sudo` (auto-installed by the `.deb`'s `postinst`) |
| Sudoers rule | `/etc/sudoers.d/proxy-jail` grants `NOPASSWD: /usr/bin/proxy-jail` to all users |
| What the rule permits | **Only** the `proxy-jail` binary — not `ip`, `iptables`, `tun2socks`, or `nsenter` |
| Lifetime | Created by `postinst`, removed on `apt purge`, kept on `apt remove` |
| Application privilege | GUI apps run as the invoking user (`SUDO_UID`), not as root |

### What this is *not*

- **Not rootless in the `yayatht` / `bubblewrap` sense** — no unprivileged
  user namespaces are used. The kernel does not need `CONFIG_USER_NS` for
  normal users, but `proxy-jail` itself always runs as real root while
  building the netns and starting `tun2socks`.
- **Not a sandbox for untrusted code** — the same user that invokes
  `proxy-jail` also gets root through it. Do not run this on a multi-user
  host you do not control, or restrict the sudoers rule to specific users
  (replace `ALL` with a user list in `/etc/sudoers.d/proxy-jail`).
- **Not a TTY-bound interactive sudo** — `proxy-jail` will refuse to prompt
  for a password. If you see `sudo: a password is required`, the sudoers
  rule is missing or `NOPASSWD` was dropped.

### If you want true rootless operation

proxy-jail cannot currently do this. Alternatives that do:

- [`yayatht`](https://github.com/hmgle/yayatht) — same SOCKS5 use case, but
  rootless via Linux 6.6+ unprivileged user namespaces (experimental, 0.1.0).
- [`bubblewrap`](https://github.com/containers/bubblewrap) — generic
  user-namespace sandbox; you would still need to combine it with a
  userspace network stack (Slirp4netNS, pasta) and a SOCKS5 client.

## Security considerations

- Privileged operations go through sudo with a scoped sudoers rule
  (`NOPASSWD: /usr/bin/proxy-jail` only) — see [Privilege model](#privilege-model)
- Configuration and runtime files are stored in user directories
  (`~/.config/proxy-jail/`, `$XDG_RUNTIME_DIR/proxy-jail/`)
- Applications run with dropped privileges (the invoking user via
  `SUDO_UID`, not root)
- Network isolation is complete - no traffic leaks outside the proxy
- DNS queries are also proxied (no DNS leaks)

## Limitations

- Linux only (requires network namespaces)
- Requires SOCKS5 proxy (no support for other proxy protocols)
- No GUI management interface (CLI only)
- Some applications may not work correctly with network namespace isolation

## Development
### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Releasing

Push a `v*` tag to trigger the GitHub Actions workflow, which builds `.deb`
packages for `amd64` and `arm64` and attaches them to a GitHub Release:

```bash
git tag v1.0.0
git push --tags
```

To build a `.deb` locally:

```bash
scripts/fetch-tun2socks.sh           # downloads tun2socks for current arch
cargo deb                            # outputs target/debian/proxy-jail_*.deb
```

## License

MIT
