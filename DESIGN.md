> **总纲**：本文件服从 [`../DESIGN.md`](../DESIGN.md)（UNIX 风格，Windows 语义）。
> 命令命名、分层归属、诚实原则均以总纲为准；此处只写 wmng 的具体设计。

# wmng 设计文档

> Windows 系统管理 applet 集：UNIX 语法 + Windows 原生对象模型。
> 版本：草案 v0.1 · 2026-11-06

---

## 1. 定位与边界

### 1.1 它是什么

`wmng.exe` 是一个**多调用二进制**（busybox 形态），提供 UNIX 风格的 Windows 系统管理命令，用于补足 coreutils/WinuxCmd 覆盖不到的那部分——即"Windows 与 UNIX 在系统模型上根本不同、当前只能用 PowerShell 完成"的能力。

### 1.2 它不是什么

| 不做 | 理由 |
|---|---|
| GNU/POSIX 兼容层 | 目标不是兼容，是 UNIX **风格**的 Windows 管理 |
| 通用命令实现（ls/cat/sort…） | 已由 coreutils / WinuxCmd 覆盖，见第 2 节选型 |
| 虚拟文件系统 / 路径空间 | 已否决：真实文件必然不同步，WinFsp 需内核驱动 |
| 通用 WMI/CIM 查询 | 用具体原生 API 逐项替代，不做通用查询语言 |
| shell 语义（管道/重定向/变量） | 归 niu/rubash，wmng 只是被调用的命令 |

### 1.3 三个二进制的关系

```
niu.exe            shell：只解释语言，不认识任何具体命令
coreutils.exe     通用 UNIX 命令（待选型：WinuxCmd vs Microsoft Coreutils）
wmng.exe        本文件：Windows 管理 applet
```

三者通过**硬链接 shim 落到 PATH**，由 niu 启动时注入。wmng 不依赖 niu，可独立使用。

---

## 2. 设计原则

1. **照搬 FreeBSD 的 CLI 约定，不发明语法。**
   FreeBSD 默认不挂 procfs，ACL 用原生 NFSv4 语法，依然是完整类 UNIX。这是本项目最直接的先例。
2. **UNIX 语法 + 原生对象模型。**
   接口是 `命令 + 选项 + 对象名`，后端是 Win32 API。不做对象到文件的映射。
3. **NFSv4 ACL 语法作为 ACL 的命令面。**
   NFSv4 ACL 与 Windows ACE 在权限位、继承标志、allow/deny、顺序求值上近乎 1:1（见 §4.1），可直接沿用 FreeBSD `setfacl(1)` 的语法。
4. **默认只读。** 所有写操作需显式选项；破坏性操作需 `-f` 或交互确认。
5. **`--json` 是结构化出口。**
   放弃对象管道后，用 JSON + `jq` 承担 PowerShell 的对象过滤角色。
6. **错误信息 coreutils 风格。** `prog: object: message`，exit code 语义化。
7. **零内核组件、零驱动、零服务。** 纯用户态，可移植解压即用。

---

## 3. 架构

### 3.1 进程形态

多调用二进制，`argv[0]` 的 basename 决定 applet：

```
wmng.exe                      → 列出 applet / 显示帮助
wmng.exe getfacl <path>       → 显式 applet 名
getfacl.exe → wmng.exe        → 硬链接 shim，argv[0] 分发
```

链接农场由 `wmng --link-dir <dir>` 生成（硬链接；跨卷或文件系统不支持时退化为拷贝或转发 shim）。

### 3.2 分层

```
┌─────────────────────────────────────┐
│ applets/      每个 applet 一个模块   │  CLI 解析、输出格式化
├─────────────────────────────────────┤
│ model/        与平台无关的领域模型    │  ACL 条目、进程记录、服务记录…
│               （可在 WSL 单测）      │
├─────────────────────────────────────┤
│ providers/    Win32 绑定层           │  windows-sys 调用、句柄 RAII
├─────────────────────────────────────┤
│ output/       表格 / TSV / JSON      │
└─────────────────────────────────────┘
```

**关键约束：`model/` 不得包含任何 Win32 调用。** 这样 ACL 字符串解析、权限位映射、格式化逻辑可以在 WSL 里跑单元测试，无需 Windows。

### 3.3 crate 选择

| crate | 用途 | 说明 |
|---|---|---|
| `windows-sys` | 绝大多数 Win32 C API | 已验证 0.59 与 0.61.2 可用；建议 0.61.2（新项目），若要复用 niu 的类型则锁 0.59 |
| `windows` | COM 接口 | 仅计划任务、ADSI（域账户）需要；其余避免 COM |
| `windows-result` | `HRESULT` → `Result` | |
| `serde` / `serde_json` | `--json` | |
| `anyhow` 或自建错误类型 | 错误上下文 | 建议自建，便于 exit code 映射 |

已验证的 `windows-sys` feature（16 个，`cargo add` 实测通过）：

```
Win32_Security, Win32_Security_Authorization,
Win32_System_Services, Win32_System_Threading,
Win32_System_ProcessStatus, Win32_System_Diagnostics_ToolHelp,
Win32_System_Registry, Win32_System_EventLog, Win32_System_Ioctl,
Win32_NetworkManagement_NetManagement, Win32_NetworkManagement_IpHelper,
Win32_Devices_DeviceAndDriverInstallation, Win32_Storage_FileSystem,
Win32_System_SystemInformation, Win32_System_Console, Win32_UI_Shell
```

### 3.4 错误模型与 exit code

| code | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 一般错误（对象不存在、权限不足等） |
| 2 | 用法错误（选项非法、参数缺失） |
| 3 | 部分失败（递归操作中有对象失败，对齐 coreutils 的"继续但报错"） |

**权限不足必须明确区分"拒绝访问"与"对象不存在"**——这是 Windows 管理脚本最常见的调试陷阱（ACL 不允许读取时返回 `ERROR_ACCESS_DENIED` 而非 `ERROR_FILE_NOT_FOUND`）。

### 3.5 输出与编码

- 默认输出**对齐表格**（人类可读）；`-q` 只出数据；`--json` 出机器可读
- 直接写 **UTF-8 字节**，配合 VT 模式，不走代码页转换
- 不做任何 CRLF 翻译（二进制安全）
- 数值默认解析为名称；`-n` 强制数值（对齐 FreeBSD `getfacl -n`）

---

## 4. 功能域分解

优先级：**P0** = 替代 PowerShell 的核心，**P1** = 常用，**P2** = 补充，**P3** = 可选。

### D1. ACL / 安全描述符（P0）

**命令**：`getfacl`、`setfacl`

**语法**：完全沿用 FreeBSD `setfacl(1)`

```
getfacl [-R] [-q] [-n] [-i] [-v] [file...]
setfacl [-R] [-b] [-m entries] [-x entries|position] [-M file] [-X file] [file...]
```

条目格式：`tag[:qualifier]:permissions[:inherit]:type`

```
setfacl -m owner@:rwxp:fd:allow,group:Users:r:d:allow file.txt
getfacl a | setfacl -b -M - b
```

**NFSv4 ↔ Windows 映射（14/14 权限位对应）**

| NFSv4 | 长名 | Windows |
|---|---|---|
| `r` | read_data | `FILE_READ_DATA` |
| `w` | write_data | `FILE_WRITE_DATA` |
| `p` | append_data | `FILE_APPEND_DATA` |
| `x` | execute | `FILE_EXECUTE` |
| `d` | delete | `DELETE` |
| `D` | delete_child | `FILE_DELETE_CHILD` |
| `a` | read_attributes | `FILE_READ_ATTRIBUTES` |
| `A` | write_attributes | `FILE_WRITE_ATTRIBUTES` |
| `R` | read_xattr | `FILE_READ_EA` |
| `W` | write_xattr | `FILE_WRITE_EA` |
| `c` | read_acl | `READ_CONTROL` |
| `C` | write_acl | `WRITE_DAC` |
| `o` | write_owner | `WRITE_OWNER` |
| `s` | synchronize | `SYNCHRONIZE` |

集合：`read_set` / `write_set` / `modify_set` / `full_set`

| NFSv4 继承标志 | Windows ACE flag |
|---|---|
| `f` file_inherit | `OBJECT_INHERIT_ACE` |
| `d` dir_inherit | `CONTAINER_INHERIT_ACE` |
| `i` inherit_only | `INHERIT_ONLY_ACE` |
| `n` no_propagate | `NO_PROPAGATE_INHERIT_ACE` |
| `I` inherited | `INHERITED_ACE` |

标签：`owner@` → Owner Rights SID `S-1-3-4`；`group@` → 对象主组；`everyone@` → `S-1-1-0`

**API 路径**

| 操作 | API |
|---|---|
| 读 SD | `GetNamedSecurityInfoW` → `GetSecurityDescriptorDacl` → `GetAclInformation`/`GetAce` |
| 写 DACL | `SetEntriesInAclW`（合并+规范化）→ `SetNamedSecurityInfoW` |
| 递归 | `TreeSetNamedSecurityInfoW`（需 `SE_RESTORE_NAME`） |
| 名称解析 | `LookupAccountSidW` / `LookupAccountNameW` / `ConvertSidToStringSidW` |
| 控制位 | `GetSecurityDescriptorControl`（`SE_DACL_PROTECTED`、`SE_DACL_AUTO_INHERITED`） |
| 访问校验 | `AccessCheck`（用于 `--test` 预测） |

**陷阱（按严重度排序）**

1. **规范顺序（canonical order）强制。** Windows 要求显式 ACE 在继承 ACE 之前、deny 在 allow 之前。FreeBSD 的 `-a position`（按位置插入）会产生非法 DACL，**必须重新规范化**，或用 `SetEntriesInAclW` 完成合并。
2. **继承 ACE 只读。** 无法直接修改/删除继承来的 ACE；必须改父目录，或设 `SE_DACL_PROTECTED` 断开继承。
3. **`owner@` 语义不同。** Windows 中对象 owner 恒定拥有 `READ_CONTROL|WRITE_DAC`（隐式），无法像 NFSv4 那样 deny。必须文档化此差异。
4. **只改 DACL 时不要传 owner/SACL 参数**，否则可能清空它们（`icacls` 历史 bug）。
5. **SACL 需要 `SE_SECURITY_NAME` 特权**（管理员 + 特权启用）。
6. **长路径 > MAX_PATH**：需 `\\?\` 前缀 + manifest `longPathAware`。
7. **对象型 ACE**（`OBJ_INHERIT`）用于 AD 对象；文件不涉及，但服务/注册表 SD 可能含，需能原样透传而不破坏。

**待扩展（NFSv4 无法表达的 Windows 概念）**

| 概念 | 命令面 |
|---|---|
| SACL / 审计 | `setfacl --sacl`（独立开关，不污染 NFSv4 语法） |
| 完整性级别 `S-1-16-*` | `chmls`（或 `setfacl --integrity`） |
| 特权 | `privs`（见 D8） |

---

### D2. 进程（P0）

**命令**：`ps`、`procstat`、`pgrep`、`pkill`、`kill`

```
ps [-ef] [-o fields] [--json]
procstat [-h handles] [-t threads] [-i] <pid>
pgrep [-f] [-u user] <pattern>
kill [-SIGNAL] <pid...>          # TERM/KILL/INT/BRK
```

**API 路径**

| 操作 | API |
|---|---|
| 基础枚举 | `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` + `Process32FirstW/NextW` |
| 高性能枚举 | `NtQuerySystemInformation(SystemProcessInformation)`（ntdll，windows-sys 未导出，需 raw FFI 或 `ntapi`） |
| 进程详情 | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`、`QueryFullProcessImageNameW`、`GetProcessTimes`、`K32GetProcessMemoryInfo`、`GetProcessIoCounters` |
| 身份 | `OpenProcessToken` + `GetTokenInformation`（`TokenUser`/`TokenIntegrityLevel`/`TokenElevation`/`TokenSessionId`） |
| 会话 | `ProcessIdToSessionId`、`WTSEnumerateSessionsW` |
| 优雅终止 | 控制台：`GenerateConsoleCtrlEvent`；GUI：`EnumWindows` + `PostMessage(WM_CLOSE)` |
| 强制终止 | `TerminateProcess` |
| 进程树 | `CreateJobObject` + `AssignProcessToJobObject` + `TerminateJobObject` |

**陷阱**

1. **pid 复用**：打开句柄后必须用创建时间校验，避免操作错进程。
2. **`PROCESS_QUERY_LIMITED_INFORMATION` 优先**——用 `PROCESS_QUERY_INFORMATION` 会大量拒绝访问（系统进程）。
3. **UAC 过滤令牌**：非提权管理员进程的 token 中 `BUILTIN\Administrators` 是 deny-only SID，影响 `AccessCheck` 结果与 `ps` 报告的组信息。
4. **`kill` 默认应是 TERM 语义（优雅）**，`-KILL` 才 `TerminateProcess`。这与 PowerShell 的 `Stop-Process` 默认强杀相反，是刻意的 UNIX 风格。
5. **僵尸/挂起状态判定**需要 `NtQuerySystemInformation` 的 `ProcessState`，`Toolhelp` 拿不到。

---

### D3. 服务（P0）

**命令**：`service`

```
service -l                        # 列出（对齐 FreeBSD rcctl 风格）
service <name> status
service <name> start|stop|restart|pause|continue
service <name> enable|disable     # 启动类型
service <name> config             # 依赖、失败动作、描述
```

**API 路径**

| 操作 | API |
|---|---|
| 枚举 | `OpenSCManagerW` + `EnumServicesStatusExW` |
| 状态 | `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)` |
| 控制 | `StartServiceW`、`ControlService` |
| 启动类型 | `ChangeServiceConfigW` |
| 配置 | `QueryServiceConfigW`、`QueryServiceConfig2W` |
| 变更通知 | `NotifyServiceStatusChangeW` |
| 服务 ACL | `QueryServiceObjectSecurity` / `SetServiceObjectSecurity` |

**陷阱**

1. `SERVICE_STOP_PENDING` 需要轮询等待，不能立即返回成功。
2. 有依赖服务的服务 stop 会失败，需先处理依赖。
3. `DeleteService` 只是标记删除，句柄全部关闭前服务仍存在。
4. 多数操作需管理员；非提权时应给出明确的"需要提权"错误，而不是笼统拒绝。

---

### D4. 注册表 / 系统参数（P1）

**命令**：`reg`、`sysctl`

```
reg ls   <key>                    # 子键 + 值
reg get  <key>\<value>
reg set  <key>\<value> --type dword|sz|expand|multi|binary <data>
reg rm   <key> | <key>\<value>
reg tree <key> [-d depth]
sysctl [-a] [key[=value]...]      # FreeBSD 风格：key: value 一行一条
```

**API 路径**

| 操作 | API |
|---|---|
| 键/值枚举 | `RegOpenKeyExW`、`RegEnumKeyExW`、`RegEnumValueW` |
| 读/写 | `RegQueryValueExW`、`RegSetValueExW` |
| 删除 | `RegDeleteKeyExW`、`RegDeleteValueW` |
| 变更通知 | `RegNotifyChangeKeyValue` |
| 键 ACL | `RegGetKeySecurity` / `RegSetKeySecurity` |

**陷阱**

1. **32/64 位视图**：必须显式带 `KEY_WOW64_64KEY` / `KEY_WOW64_32KEY`，否则结果取决于调用进程位数——静默错误。
2. **类型必须显式**：`cat` 式文本往返会把 `REG_DWORD` 退化成 `REG_SZ`。`reg set` 强制 `--type`。
3. `REG_BINARY` 输出需 base64 或 hex，不能直接打二进制。
4. `sysctl` 不做"注册表全量映射"，而是**精选参数表**（OS 版本、CPU 数、页大小、时区、长路径开关、环境变量等），来源可以是 API 或注册表。

---

### D5. 用户与组（P1）

**命令**：`pw`、`getent`、`id`

```
pw usershow [-a] [user]
pw useradd <user> [-m] [-G groups]
pw usermod <user> [-G groups] [-L|-U]   # 锁定/解锁
pw userdel <user> [-r]
pw groupshow [-a] [group]
pw groupadd|groupmod|groupdel
getent passwd|group [name]
id [-Gnru] [user]
```

**API 路径**

| 操作 | API |
|---|---|
| 枚举 | `NetUserEnum`、`NetLocalGroupEnum`、`NetLocalGroupGetMembers` |
| 详情 | `NetUserGetInfo`、`NetUserGetLocalGroups` |
| 增删改 | `NetUserAdd`、`NetUserDel`、`NetUserSetInfo`、`NetLocalGroupAddMembers` |
| SID 解析 | `LookupAccountNameW` / `LookupAccountSidW` |

**陷阱**

1. `netapi32` 只覆盖**本地账户（SAM）**；域账户需 ADSI/LDAP，v1 明确不支持。
2. 密码设置、组变更需管理员。
3. 用户主目录与 SID 的对应关系不在 SAM 里，需 `ProfileList` 注册表。

---

### D6. 文件属性（P1）

**命令**：`chflags`、`lsattr`（或扩展 `ls -o`）

```
chflags [+-]readonly,hidden,system,archive,noindex <path...>
chflags -R ...
```

**API 路径**：`GetFileAttributesW` / `SetFileAttributesW`；压缩与稀疏用 `DeviceIoControl(FSCTL_SET_COMPRESSION / FSCTL_SET_SPARSE)`；重解析点用 `FSCTL_GET_REPARSE_POINT`。

**陷阱**：`READONLY` 会导致后续写入失败（与 POSIX 只读位不同，后者只影响非 root 写入）；`SYSTEM`/`HIDDEN` 影响资源管理器显示。

---

### D7. 事件日志（P2）

**命令**：`dmesg`、`eventlog`

```
eventlog -l                                  # 列出通道
eventlog -c System -n 20                     # 最近 20 条
eventlog -c System --since 1h --level error
eventlog --json
```

**API 路径**：`EvtQuery` / `EvtNext` / `EvtRender`（wevtapi，`Win32_System_EventLog`）。旧式 `OpenEventLog`/`ReadEventLog` 仅作兼容。

**陷阱**：`EvtNext` 是批量语义需循环；需要 "Event Log Readers" 组成员或管理员；XML 与文本渲染是两条路径。

---

### D8. 特权与完整性（P2）

**命令**：`privs`、`chmls`

```
privs [-a] [command]              # 列出 token 特权及启用状态（whoami /priv 替代）
privs -e SeDebugPrivilege <cmd>   # 临时启用特权执行命令
chmls [+-]Low|Medium|High|System <path...>
```

**API 路径**：`LookupPrivilegeValueW`、`AdjustTokenPrivileges`、`GetTokenInformation(TokenPrivileges)`；完整性级别用 `SetNamedSecurityInfoW` 改 SACL 中的 `SYSTEM_MANDATORY_LABEL_ACE`。

---

### D9. 设备 / 存储 / 网络（P2–P3）

| 命令 | 用途 | API |
|---|---|---|
| `devinfo` | 设备枚举 | `SetupDiGetClassDevsW`、`SetupDiEnumDeviceInfo`、`SetupDiGetDeviceRegistryPropertyW` |
| `df` / `lsblk` | 卷与容量 | `GetLogicalDrives`、`GetDiskFreeSpaceExW`、`GetVolumeInformationW`、`GetDriveTypeW` |
| `ifconfig` | 网络接口与地址 | `GetAdaptersAddresses` |

---

### D10. 电源（P1）

**命令**：`shutdown`、`reboot`、`poweroff`（已实现）；`power`（计划中，见下）

```
shutdown [-p | -r] [-f] [-c] [now | +minutes | hh:mm] [message ...]
reboot [-f]                        # = shutdown -r now
poweroff [-f]                      # = shutdown -p now
```

参照 **FreeBSD shutdown(8)**，机制用 `InitiateSystemShutdownExW`（超时秒数 = 用户看到的倒计时，消息 = 广播对话框，`-f` = 强制关闭应用）与 `AbortSystemShutdownW`（`-c`）。两者需 `SeShutdownPrivilege`，非提权报"run elevated"。

**裁剪与偏离**：

| 项 | 处置 | 理由 |
|---|---|---|
| `halt` | **命令不存在** | Windows 无"停机保持供电"状态；不留别名不留墓碑（总纲判据二） |
| `shutdown` 默认动作 | poweroff（FreeBSD 默认 halt） | 同上，取最不意外的读法 |
| 单用户模式 | 砍掉 | `shutdown now` 即立即执行，不降级 |
| `-f` | 语义为 Windows 强制关应用 | FreeBSD 的 fsck 标志在此无意义 |
| 关机原因码 | 恒报 PLANNED | Windows 特有概念，无 UNIX 对应，不上命令面 |

**计划中（`power`，电源计划）**：`power -l`（列方案）、`power -s <guid|name>`（激活）、逐项读写（超时/亮度等，`PowerEnumerate` / `PowerReadACValueIndex` / `PowerWriteACValueIndex` / `PowerSetActiveScheme`）。替代 `powercfg /list`、PowerShell `powercfg` 调用。

### D11. 计划任务（P1，计划中）

**命令**：`cron`、`crontab`

```
crontab -l                     # 列出本用户注册的任务
crontab -r <file>              # 以文件内容替换任务集
cron -l                        # 列出全部（管理员）
```

参照 FreeBSD cron/crontab 的**命令面**；机制是 Task Scheduler（COM `ITaskService`），cron 五字段时间表达式编译为 Task Scheduler 触发器。需 `windows` crate（唯一引入 COM 的域，§3.3）。

**映射要点**：
- 每个用户一个"任务文件夹"（`\znie\wmng`），crontab 语法行 ↔ 单个 Task；`-l`/`-r` 是列出/整体替换，与 FreeBSD 的编辑器语义一致
- cron 无对应的概念（运行级别、`@reboot` 之外的 at-spool）明确报错
- PowerShell `Get-ScheduledTask` / `Register-ScheduledTask` / `schtasks` 全部由此替代

### D12. 后续域（P3，暂不设计）

| PowerShell 能力 | 建议 UNIX 映射 | 备注 |
|---|---|---|
| 防火墙 `Get-NetFirewallRule` | `pfctl` 风格 | 需 `INetFwPolicy2` COM |
| 证书存储 `Cert:` | `certs` | `CertOpenStore` / `CertEnumCertificatesInStore` |

---

## 5. 实现路径（里程碑）

### M0 — 骨架（可交付：`wmng --list` 可用）

- 多调用分发（`argv[0]` + 显式 applet 名）
- `--list` / `--help` / `--version`
- `--link-dir` 硬链接农场生成
- 错误模型 + exit code 映射 + 统一错误格式
- 输出层：表格 / TSV / `--json`
- `model/` 与 `providers/` 分层落地（含"model 不得调用 Win32"的 CI 检查）
- Windows CI：`cargo fmt --check` + `cargo build` + 骨架单测

**验收**：`wmng --list` 列出空 applet 表；错误路径 exit code 正确；model 层单测可在 WSL 跑通。

### M1 — ACL（可交付：`getfacl`/`setfacl` 可替代 `icacls` 只读与基本写入）

- `getfacl`：读 DACL → NFSv4 格式；`-q`/`-n`/`-i`/`-v`
- `setfacl`：`-m`/`-x`/`-b`/`-M`/`-X`/`-R`
- `--json` 输出
- 规范顺序规范化
- 差分测试：与 PowerShell `Get-Acl` 对比

**验收**：`getfacl | setfacl -M -` 往返幂等；递归设置与 `icacls /T` 结果一致；差分测试全绿。

### M2 — 进程（可交付：`ps`/`pgrep`/`kill` 可替代 `Get-Process`/`Stop-Process`）

- `ps` 基础与 `-o` 字段选择
- `pgrep`/`pkill`
- `kill` 优雅/强制两条路径
- `procstat` 详情（token、句柄、线程）
- 差分测试：与 `Get-Process` 对比 PID/名称/内存

### M3 — 服务 + 注册表（可交付：`service`、`reg`、`sysctl`）

- `service` 全操作 + 等待语义
- `reg` 读 + 写（含 `--type`）
- `sysctl` 精选参数表
- 差分测试：与 `Get-Service`、`Get-ItemProperty` 对比

### M4 — 补充域

`chflags`、`privs`、`chmls`、`pw`/`getent`、`eventlog`、`devinfo`/`df`/`ifconfig`

### M5 — 集成与发布

- 补全生成（bash/zsh，沿用 niu 的生成器思路）
- man 页
- niu 侧 PATH 注入接入（`wmng` 与 `coreutils` 并列）
- 打包与安装器

---

## 6. 跨领域技术风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| **规范顺序 / 继承语义** | ACL 写坏 = 文件不可访问 | M1 先用 `SetEntriesInAclW` 完成合并；对所有写入做"写后重读校验" |
| **UAC 过滤令牌** | 提权/非提权行为不一致，测试难复现 | 测试矩阵覆盖三种上下文；错误信息明确区分"拒绝访问"与"需要提权" |
| **MAX_PATH** | 长路径操作失败 | manifest `longPathAware` + 内部统一 `\\?\` 规范化 |
| **32/64 位注册表视图** | 静默读到错误数据 | 强制显式视图参数，默认 64 位 |
| **编码** | 中文路径/输出乱码 | 全程 UTF-16 ↔ UTF-8 边界转换；输出直接写 UTF-8 字节 |
| **危险操作** | 误删服务/改系统 ACL | 默认只读；破坏性操作需 `-f`；`--dry-run` 全局支持 |
| **不可测的纯 Win32 逻辑** | 大量代码只能人工验证 | `model/` 严格无 Win32；解析/格式化/映射全部单测 |

---

## 7. 测试策略

### 7.1 三层

| 层 | 位置 | 说明 |
|---|---|---|
| 单元（WSL 可跑） | `model/` | ACL 条目解析、权限位映射、格式化、规范顺序算法 |
| 集成（Windows） | `tests/` | 临时目录 + 真实 ACL/进程/服务，验证 API 路径 |
| 差分（Windows） | `tests/diff/` | **以 PowerShell 为 oracle**：`Get-Acl` / `Get-Process` / `Get-Service` / `Get-ItemProperty` |

### 7.2 权限矩阵

每个写操作在三种上下文下测试：

1. 提权管理员
2. 非提权管理员（UAC 过滤令牌）
3. 标准用户

预期结果必须是**确定的**：成功，或明确的 `ERROR_ACCESS_DENIED` / 需要提权提示。

### 7.3 幂等与往返

- `getfacl X > a; setfacl -b -M a X; getfacl X > b; diff a b` 必须为空
- 重复 `setfacl` 同一参数应无变化（幂等）

---

## 8. 待决问题

| # | 问题 | 备选 | 建议 |
|---|---|---|---|
| 1 | `getfacl` 与 WinuxCmd 现有命令冲突 | 接管 / 改名 `winfacl` | 接管，WinuxCmd 版本不进 PATH |
| 2 | 仓库形态 | 独立 `unixwin/wmng` / niubash monorepo | 独立仓库，与 niu 解耦 |
| 3 | `windows-sys` 版本 | 0.59（对齐 niu）/ 0.61.2（最新） | 0.61.2，独立二进制无冲突 |
| 4 | `--json` schema 是否版本化 | 是 / 否 | 是，`{"schema": 1, ...}` |
| 5 | 是否支持远程（远程 SCM/注册表） | 支持 / 仅本地 | 仅本地，v1 明确不支持 |
| 6 | `kill` 默认信号 | TERM（优雅）/ KILL（强杀） | TERM，与 PowerShell 相反是刻意设计 |
| 7 | 是否实现 `--dry-run` 全局开关 | 全局 / 逐命令 | 全局 |

---

## 9. 附：PowerShell 覆盖矩阵

| PowerShell 能力 | wmng 命令 | 域 | 优先级 |
|---|---|---|---|
| `Get-Acl` / `Set-Acl` / `icacls` | `getfacl` / `setfacl` | D1 | P0 |
| `Get-Process` / `Stop-Process` | `ps` / `procstat` / `kill` | D2 | P0 |
| `Stop-Computer` / `Restart-Computer` | `shutdown` / `reboot` / `poweroff` | D10 | P1 |
| `powercfg`（电源计划） | `power` | D10 | P1 |
| `Get-Service` / `Start-Service` | `service` | D3 | P0 |
| `Get-ItemProperty HKLM:` | `reg` / `sysctl` | D4 | P1 |
| `Get-LocalUser` / `Get-LocalGroup` | `pw` / `getent` / `id` | D5 | P1 |
| `Get-Item`（属性） | `chflags` / `lsattr` | D6 | P1 |
| `Get-WinEvent` | `eventlog` / `dmesg` | D7 | P2 |
| `whoami /priv` | `privs` | D8 | P2 |
| `Get-PnpDevice` | `devinfo` | D9 | P2 |
| `Get-Volume` / `Get-Disk` | `df` / `lsblk` | D9 | P2 |
| `Get-NetIPConfiguration` | `ifconfig` | D9 | P2 |
| `Get-ScheduledTask` / `schtasks` | `cron` / `crontab` | D11 | P1 |
| `Get-NetFirewallRule` | `pfctl` | D12 | P3 |
| `Get-ChildItem Cert:` | `certs` | D12 | P3 |
| `Get-CimInstance`（通用） | **不实现** | — | — |
| 对象管道 / `Format-Table` | **不实现**（`--json` + `jq` 替代） | — | — |
