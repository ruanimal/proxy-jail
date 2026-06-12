## Plan: Proxy Jail — 强制 GUI 应用走 SOCKS5 代理

基于 Network Namespace + tun2socks 隔离特定桌面应用的全网络流量，以 Rust 单二进制 + file capabilities 实现零 sudo、对应用完全透明的代理方案。

### 架构概览

每个 "Jail" 包含：独立 Network Namespace → veth pair 连接宿主机 → tun2socks (TUN 设备) 将所有 IP 流量转为 SOCKS5 → 宿主机/局域网 SOCKS5 代理出站。

```
GUI App ──► TUN (tun2socks) ──► SOCKS5 ──► 互联网
  (netns: pj-work)
```

### 关键决策

- **Rust 单二进制**：`/usr/bin/proxy-jail`，通过 `setcap cap_net_admin,cap_sys_admin,cap_setuid,cap_setgid+ep` 赋予权限，用户直接运行无须 sudo/polkit/daemon
- **tun2socks**：代理后端，全协议透明（TCP/UDP/DNS/ICMP），另需 `setcap cap_net_admin+ep`
- **惰性初始化**：首次 `proxy-jail app run` 时创建 netns + veth + tun2socks，不销毁
- **tun2socks 进程管理**：孤儿进程托管给 init，通过 PID 文件追踪存活状态。`app run` 时检查 `/proc/{pid}/status`，已退出则自动重启。默认不销毁，用户可手动 `jail stop` 清理
- **nsenter 启动**：`setns()` 进入命名空间 → `setuid()` 降权 → `exec()` 应用进程
- **桌面集成**：`~/.local/share/applications/` 下生成覆盖 .desktop 文件
- **多对一**：多个应用共享同一个 Jail

### 目标平台与兼容性

- **最低目标**：Ubuntu 24.04、Debian 12、Fedora 38、Arch（均使用 systemd 248+，D-Bus socket 为文件系统路径，无 abstract socket 兼容问题）
- **防火墙**：统一使用 `iptables` 命令。所有现代发行版均提供（iptables-legacy 或 iptables-nft 翻译层），无需区分 nftables/iptables 后端。仅使用一条 `POSTROUTING MASQUERADE` 规则，两种后端均等效
- **内核要求**：`CONFIG_NET_NS=y`、`CONFIG_TUN=y`、`CONFIG_VETH=y`（均为主流发行版默认配置）
- **运行前提**：`iproute2`（提供 `ip` 命令）、`iptables`、`tun2socks` 二进制

---

### 阶段一：项目骨架搭建

**1. 初始化 Rust 项目**
- `cargo init` 在 `/Users/ruan/projects/proxy-jail`
- 配置 `Cargo.toml`：依赖 clap (derive)、serde + serde_yaml + serde_json、anyhow、tracing
- 单 binary target：`proxy-jail`

**2. 目录结构**
```
src/
├── main.rs          # CLI 入口，路由到子命令
├── config.rs        # YAML 配置加载 (serde_yaml)
├── jail.rs          # Jail 生命周期：检查状态、惰性创建、并发锁
├── network.rs       # netns / veth / 路由 / iptables NAT（调用 ip/iptables 命令）
├── proxy.rs         # tun2socks JSON 配置生成与进程管理 (serde_json)
├── launcher.rs      # setns → setuid → exec GUI 应用
├── desktop.rs       # .desktop 文件生成
└── log.rs           # 日志初始化 (tracing + env_logger)
```

> 注：tun2socks 模式下不需要 iptables REDIRECT，仅需路由规则。`dns.rs` 也不需要——tun2socks 在 L3 层接管 DNS。两个模块已移除。

**3. 配置模型**
- 全局配置路径：`/etc/proxy-jail/config.yaml`
- 运行时目录：`/run/proxy-jail/<jail-name>/`（PID 文件、tun2socks 配置）
- 配置结构：全局 `jails` 列表，每个 jail 含 `name`、`proxy`（host/port/type/auth）、`apps`（command/args/display_name）

**4. CLI 命令规划**

```
proxy-jail jail create <name> --socks5 <host:port>   # 定义 jail
proxy-jail jail list                                  # 查看所有 jail 状态
proxy-jail jail stop <name>                           # 停止 jail（杀 tun2socks + 删 netns）
proxy-jail jail delete <name>                         # 删配置 + 调 jail stop

proxy-jail app run <jail> -- <command> [args]          # 在 jail 中运行应用
proxy-jail app stop <jail> <app>                       # 停止 jail 中某个应用
proxy-jail app desktop install <jail> <app>            # 生成 .desktop 入口
proxy-jail app desktop uninstall <jail> <app>          # 移除 .desktop 覆盖
```

---

### 阶段二：核心功能实现

**5. 网络命名空间管理 (`network.rs`)**
- `create_jail_network(name, subnet)`：`ip netns add pj-{name}` → 创建 veth pair → 分配 IP → 宿主机 NAT (`iptables -t nat -A POSTROUTING -s {subnet} -j MASQUERADE`) → 启用 ip_forward
- `destroy_jail_network(name)`：杀 tun2socks（通过 PID 文件）→ 删除宿主机 iptables NAT 规则 (`iptables -t nat -D POSTROUTING -s {subnet} -j MASQUERADE`) → 删除 netns → 删除 veth pair → 清理运行时目录
- `check_jail_exists(name)`：检查 `/var/run/netns/pj-{name}` 是否存在
- 子网自动分配（`10.10.0.0/24`、`10.10.1.0/24`...）或手动指定
- **并发锁**：初始化前 `flock(/run/proxy-jail/{name}.lock)`，防止两个 `run` 同时创建同一个 jail

**6. tun2socks 集成与进程管理 (`proxy.rs`)**
- 生成 tun2socks 配置文件：**JSON 格式**（xjasonlyu/tun2socks 使用 JSON），包含 TUN 设备名、IP、MTU、SOCKS5 地址
- `ip netns exec pj-{name} tun2socks -config ...` 启动为子进程
- 路由配置：命名空间内默认路由指向 TUN 设备，代理服务器地址绕过 TUN 走 veth

**进程生命周期管理：**

- **启动方式**：proxy-jail `fork()` 后，子进程执行 `ip netns exec` 启动 tun2socks。proxy-jail 不 `wait()`，直接进入 `exec app` 流程。tun2socks 的父进程（`ip netns exec`）在 proxy-jail exec 后变孤儿，被 init (PID 1) 接管，tun2socks 持续运行。

```
proxy-jail (PID 1000)
  ├─ fork ─► ip netns exec pj-work tun2socks ... (PID 1001)
  │            └─ tun2socks (PID 1002, inside netns)
  └─ exec firefox (PID 1000 替换, PID 1001 → init)
         └─ tun2socks 持续由 init 托管 ✅
```

- **存活检测**：PID 写入 `/run/proxy-jail/{name}/tun2socks.pid`。每次 `app run` 命令检查 `/proc/{pid}/status` 是否存在 → 存在则复用，否则重新启动 tun2socks。
- **崩溃恢复**：tun2socks 退出时 PID 文件过时。下次 `app run` 检测到 PID 无效，自动重新拉起，应用无感知。
- **手动停止**：`jail stop <name>` 通过 PID 文件向 tun2socks 发 SIGTERM，然后删除 netns、veth pair、宿主机 iptables NAT 规则，清理运行时目录。
- **手动停应用**：`app stop <jail> <app>` 按命令名匹配 netns 内进程（排除 tun2socks），发 SIGTERM 停止指定应用，tun2socks 和 netns 保留。
- **已知待验证**：`ip netns exec` 产生父子两个进程，PID 文件应记录 tun2socks 自身（子进程）的 PID。需实现时验证 `ip netns exec` 退出时子进程是否会跟随退出，以及 SIGTERM 应发给哪个进程。

**7. 应用启动器 (`launcher.rs`)**
- `launch_app(jail_name, command, args)`：
  1. 检查 jail 是否已运行，否则惰性初始化
  2. `fork()` → 子进程通过 `/proc/self/ns/net` 或 `nsenter` 进入命名空间
  3. 用 `setresuid/setresgid` 降权到实际用户
  4. 保留 `DISPLAY`、`WAYLAND_DISPLAY`、`XAUTHORITY`、`XDG_RUNTIME_DIR`、`DBUS_SESSION_BUS_ADDRESS` 等环境变量
  5. `execvpe()` 目标应用

**8. 命名空间内路由规则（合入 `proxy.rs` 或 `network.rs`）**
- tun2socks 模式下无需 iptables REDIRECT，仅需 `ip route`：
  - 添加路由绕过规则：代理服务器 IP 走 veth 网关（`ip route add {proxy_host} via {gateway}`）
  - 默认路由指向 TUN 设备（`ip route add default dev tun0`）
- 这些规则在 tun2socks 启动后、应用 exec 前设置

---

### 阶段三：桌面集成

**9. .desktop 文件管理 (`desktop.rs`)**
- `desktop_install(jail_name, app_command)`：
  1. 从 `/usr/share/applications/` 找到源 `.desktop` 文件
  2. 解析 `Name`、`Icon`、`Exec`、`Comment` 等字段
  3. 生成 `~/.local/share/applications/pj-{jail}-{app}.desktop`
  4. 修改 `Name` 添加后缀标记（如 `Firefox (via proxy-jail: work)`）
  5. 修改 `Exec` 为 `Exec=proxy-jail app run {jail} -- {original_exec_with_placeholders}`
  6. 保留原 `Icon`，可选加标记指示

---

### 阶段四：错误处理与健壮性

**10. 错误场景**
- tun2socks 崩溃 → `app run` 时检测 `/proc/{pid}` 无效，自动重启；若应用正在运行，网络中断后应用恢复需重启应用
- SOCKS5 代理不可用 → fail-closed（应用断网），日志提示
- netns 残留 → `jail stop` 或 `jail delete` 时强制清理
- 权限不足 → 检查 capabilities，给出 `setcap` 提示
- tun2socks 未安装 → 给出安装指引
- 用户手动清理需求 → 提供 `jail stop`（停 tun2socks + 删 netns）、`app stop`（只停指定应用保留 netns）、`jail delete`（删配置 + stop）

**11. 日志**
- 使用 `tracing` + `env_logger`
- 默认日志到 `~/.local/share/proxy-jail/logs/`
- `-v` / `-vv` 控制详细程度

---

### 关键文件

- `Cargo.toml` — 项目依赖配置
- `src/main.rs` — CLI 入口
- `src/config.rs` — 配置模型与加载
- `src/network.rs` — 网络命名空间操作
- `src/proxy.rs` — tun2socks 配置与进程管理
- `src/launcher.rs` — 应用启动（setns + setuid + exec）
- `src/desktop.rs` — .desktop 文件生成
- `src/jail.rs` — Jail 生命周期编排
- `config.example.yaml` — 示例配置

---

### 验证方式

1. **单元测试**：配置解析、子网分配、.desktop 文件生成
2. **集成测试**（需要 Linux 环境）：
   - `proxy-jail jail create test --socks5 127.0.0.1:1080`
   - `proxy-jail app run test -- curl ifconfig.me` 验证出口 IP 变化
   - `proxy-jail app run test -- firefox` 验证 GUI 启动和网络隔离
   - `proxy-jail app desktop install test firefox` 验证桌面入口生成
3. **权限验证**：确保 `proxy-jail app run` 不需要 sudo 密码
4. **泄漏测试**：DNS 查询不经过宿主机、WebRTC 不泄漏真实 IP

---

### 不包括的范围

- GUI 管理界面（仅 CLI）
- systemd service 注册（手动 setcap 即可，不需要常驻 daemon）
- 非 Linux 平台（macOS/Windows）
- 代理协议除 SOCKS5 外的支持（如 Shadowsocks、VMess 直连）
