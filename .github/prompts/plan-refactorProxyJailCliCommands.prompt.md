# Plan: 重构 proxy-jail CLI 命令（三命名空间：jail / app / desktop）

## TL;DR
保留**三个对称的命名空间**：`jail` / `app` / `desktop`，命令形式遵循 `<资源> <动作>` 的对称结构（与 `iproute2`、`git`、`docker` 等工具习惯一致）。

- `app run` → `app exec --jail <name> -- <cmd>`（与 docker exec 一致）
- `app stop` → `app stop --jail <name> <app>`（保持不变）
- `app desktop install|uninstall|list` → `desktop create|delete|list --jail <name> [args]`

行为零变化。彻底移除旧的 `app desktop *` 嵌套形式。

## 重新设计后的 CLI 结构

```
proxy-jail
├── jail                                       # 命名空间，完全保留
│   ├── create <name> --socks5 <addr>          # 不变
│   ├── list                                   # 不变
│   ├── stop <name>                            # 不变
│   └── delete <name>                          # 不变
├── app                                        # 命名空间，简化
│   ├── exec --jail <name> -- <cmd> [args...]  # 原: app run
│   └── stop --jail <name> <app>               # 不变
└── desktop                                    # 命名空间（从 app desktop 提升）
    ├── create --jail <name> --from <file>     # 原: app desktop install
    ├── delete --jail <name> <file>            # 原: app desktop uninstall
    └── list [--jail <name>]                   # 原: app desktop list
```

## 关键决策（已与用户对齐）
- 三个命名空间 `jail` / `app` / `desktop` 完全保留
- `jail *` 与 `app stop` 完全不变
- `app run` 重命名为 `app exec`（与 docker exec 一致，更精确表达"在命名空间内执行命令"）
- `app desktop install|uninstall|list` 提升为 `desktop create|delete|list`（与 `jail create|delete|list` 动词完全对称）
- `uninstall` → `delete`，`install` → `create`：动词与 `jail` 命名空间一致
- **三个命名空间下所有 `jail` 参数统一改为 `#[arg(long)] jail: String` 命名参数**（跨命名空间一致）
- 不保留旧 `app desktop *` 别名
- 同步更新 `desktop.rs` 生成的 `Exec=` 行

## 实现步骤

### 1. 重写 `src/main.rs` 的 CLI 定义
- **保留** `Commands::Jail { command: JailCommands }`（`JailCommands` 四个变体不动）
- **保留** `Commands::App { command: AppCommands }`（简化后只含 `exec` 与 `stop`）
- **新增** `Commands::Desktop { command: DesktopCommands }`（含 `create` / `delete` / `list`）
- `AppCommands` 重写为：
  - `Exec { #[arg(long)] jail: String, #[arg(trailing_var_arg = true, required = true)] command: Vec<String> }` — `--` 仍为 `command` 分隔符
  - `Stop { #[arg(long)] jail: String, app: String }`
- `DesktopCommands` 替换原 `DesktopCommands`：
  - `Create { #[arg(long)] jail: String, #[arg(long)] from: String }` — `--from <file>` 表达“从某个 .desktop 文件创建 entry”，语义比位置参数更显式
  - `Delete { #[arg(long)] jail: String, desktop_file: String }`（保留位置参数，语义“删除名为 X 的 entry”已足够明确）
  - `List { #[arg(long)] jail: Option<String> }`
- 函数调用映射：
  - `AppCommands::Exec` → `jail::run_app`
  - `AppCommands::Stop` → `jail::stop_app`
  - `DesktopCommands::Create` → `desktop::desktop_install_from_file(jail_config, &from)`
  - `DesktopCommands::Delete` → `desktop::desktop_uninstall_from_file(jail_config, &desktop_file)`
  - `DesktopCommands::List` → `desktop::list_desktop_files(jail.as_deref())`

### 2. 更新 `src/desktop.rs` 的 `transform_desktop_content`
- 将所有 `proxy-jail app run {jail} -- ...` 字符串改为 `proxy-jail app exec --jail {jail} -- ...`
- 修改两处：
  - 主 `[Desktop Entry]` 的 `Exec=` 替换逻辑（约 `transform_desktop_content` 函数中段 `match key` 分支）
  - `[Desktop Action *]` 段中的 `Exec=` 替换逻辑（同一函数 `else if trimmed.starts_with("Exec=")` 分支）
- 同步更新 `test_transform_codex_desktop` 测试断言（约 5 处 `Exec=proxy-jail app run` 字符串需改写为 `proxy-jail app exec --jail ...`）

### 3. 更新 `README.md` 命令示例
- `proxy-jail app run work -- firefox` → `proxy-jail app exec --jail work -- firefox`
- `proxy-jail app desktop install work firefox` → `proxy-jail desktop create --jail work --from firefox`
- `proxy-jail app desktop uninstall work firefox` → `proxy-jail desktop delete --jail work firefox`（不变）
- `proxy-jail app stop work firefox` 保持不变
- `jail create` / `jail list` / `jail stop` / `jail delete` 示例保持不变

### 4. 验证
- `cargo build` 0 warning（AGENTS.md 硬性要求）
- `cargo test` 通过，重点确认 `desktop.rs` 中的 `test_transform_codex_desktop`
- `cargo run -- --help` 验证帮助文本反映新命令树
- 抽查生成的 .desktop 文件 `Exec=` 行格式正确

## 相关文件
- `src/main.rs` — CLI 定义与命令分派（核心改动点）
- `src/desktop.rs` — 字符串模板与测试断言（`transform_desktop_content` 函数 + `test_transform_codex_desktop`）
- `README.md` — 用户文档
- `src/jail.rs` / `src/launcher.rs` / `src/config.rs` — 无需修改

## 范围边界
**包含**：
- `AppCommands::Run` 重命名为 `AppCommands::Exec`
- `DesktopCommands` 由 `Install|Uninstall|List` 改为 `Create|Delete|List`
- `DesktopCommands::Create.from` 字段使用 `#[arg(long)]` 命名（`--from`）
- 新增 `Commands::Desktop` 顶级分组
- `AppCommands::Stop` / `JailCommands::*` 完全保留
- 所有 `jail` 字段加 `#[arg(long)]`
- `transform_desktop_content` 字符串模板更新
- 单元测试断言更新
- README 中 `app desktop *` 相关命令示例更新

**不包含**：
- `jail` 命名空间下的任何命令改动
- `app stop` 命令改动
- 新增功能或行为变化
- 配置文件格式变更
- 安装 / 卸载脚本变更

## 进一步考虑
1. `app exec` 与 `app run` 哪个更合适？`exec` 与 docker/容器生态一致，强调"在已有命名空间内执行"；`run` 更通用。本次采纳 `exec`。
2. `desktop create` 采用 `--from <file>` 命名参数（用户已采纳），强调“从源 .desktop 文件创建 entry”的语义；`desktop delete` 保留 `desktop_file` 位置参数，因为“删除名为 X 的 entry”本身已足够明确，无需额外词。
3. `app exec -- <cmd>` 中 `--` 仍是必要分隔符，与之前讨论一致。
4. 与原"扁平化"设计相比，本设计每条命令多一层路径（`app exec` vs `exec`），但命名空间更清晰、动词与 `jail` 对称。
