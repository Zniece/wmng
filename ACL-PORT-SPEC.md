# D1 ACL 实现规格：基于 FreeBSD setfacl/getfacl 源码

> 参考实现：`freebsd/freebsd-src` → `bin/setfacl/`（BSD-2-Clause）
> 本文把 FreeBSD 已验证的设计提取为 wmng 的实现规格，并标注 Windows 必须偏离的点。

---

## 0. 许可

FreeBSD 的 `bin/setfacl/*` 与 `bin/getfacl/*` 均为 **BSD-2-Clause**，与 MIT 兼容。若直接移植代码，须在每个文件保留原始版权声明（Chris D. Faulhaber / Robert N. M. Watson / TrustedBSD Project）。建议：`model/acl/` 下加 `NOTICE` 段说明来源。

---

## 1. 可直接沿用的 10 条设计

每条都来自源码，不是推测。

### 1.1 操作队列，且严格顺序敏感

`setfacl.c` 把每个选项解析成一个 `sf_entry` 压入 `TAILQ`，`handle_file` 里按队列顺序逐个应用。

**后果**：`setfacl -m a -x b -m c file` 与 `setfacl -m a -m c -x b file` 结果可能不同。man page 也明说 "The above options are evaluated in the order specified on the command-line."

**对我们的约束**：CLI 解析不能用"先归集所有 -m 再统一应用"的简化实现，必须保序。

### 1.2 `-R` 递归时，对非目录清除继承标志

`setfacl.c: clear_inheritance_flags()`，源码注释直接给了理由：

> to avoid files being assigned identical ACLs to their parent directory while also being set to inherit them.

具体规则（仅 NFSv4）：
1. 删除所有带 `INHERIT_ONLY` 的条目；
2. 从其余条目上移除 `FILE_INHERIT | DIRECTORY_INHERIT | NO_PROPAGATE_INHERIT`。

**为什么关键**：继承标志只对目录有意义。递归时若把带 `fd` 标志的条目原样套到普通文件上，会产生一个"既显式设置又声称从父目录继承"的矛盾状态。

**这条最容易漏，漏了会静默产生错误 ACL。**

### 1.3 合并的匹配键是 `(tag, qualifier[, entry_type])`

`merge.c: merge_acl()`：

- 匹配 `tag`（owner@/group@/everyone@/user/group）；
- 对 `user`/`group` 还要匹配 qualifier（SID/uid/gid）；
- **NFSv4 额外匹配 `entry_type`（allow/deny）** —— 源码注释：*"For NFSv4, in addition to 'tag' and 'id' we also compare 'entry_type'"*。

匹配成功 → 用新条目的 permset + entry_type + flagset 覆盖旧条目。
匹配失败 → 新增条目。

### 1.4 新条目前置，不是追加

`merge.c` 注释：

> NFSv4 ACL entries must be prepended to the ACL. Appending them at the end makes no sense, since in most cases they wouldn't even get evaluated.

并用 `entry_number++` 保证 `-m user:1:r:allow,user:2:r:allow` 里的多条保持输入顺序（否则会反序）。

### 1.5 `-a position` 仅对 NFSv4 有效

`add_acl()` 开头：若现有 ACL 不是 NFSv4 品牌，直接 `warnx("the '-a' option is only applicable to NFSv4 ACLs")` 并返回错误。

### 1.6 品牌（brand）不匹配是硬错误

`util.c: branding_mismatch()`：POSIX.1e ACL 与 NFSv4 ACL 不允许互相合并/删除。我们恒为 NFSv4，但需要处理"对象无 ACL"的情况（`ACL_BRAND_UNKNOWN` 时不算不匹配）。

### 1.7 `-M`/`-X` 的 ACL 文件格式：一行一条，`#` 后注释

这是 `getfacl a | setfacl -M - b` 能工作的原因——`getfacl` 输出的 `# file:` / `# owner:` / `# group:` 头部行正好是注释，被解析器自动跳过。

**我们实现时必须保持这个性质**，否则管道往返会断。

### 1.8 错误逐文件累积，不中断

`setfacl.c`: `local_error`（单文件内）+ `carried_error`（跨文件）累加，遍历继续，最终返回非零。`getfacl.c` 同理（`carried_error`）。

**对应我们的 exit code 3（部分失败）。**

### 1.9 无操作数或 `-` 时，从 stdin 读文件列表

`setfacl.c: stdin_files()`、`getfacl.c: print_acl_from_stdin()`。注意 setfacl 里 `have_stdin` 保证只能有一个 stdin 来源。

### 1.10 `-h` 与 `-R` 互斥

`setfacl.c`: `errx(1, "the -R and -h options may not be specified together.")`

---

## 2. CLI 表面（照搬）

```
getfacl [-dhnqsv] [-i] [file ...]
setfacl [-R [-H | -L | -P]] [-bdhkn] [-a position entries] [-m entries]
        [-M file] [-x entries | position] [-X file] [file ...]
```

| 选项 | 语义 | Windows 可用性 |
|---|---|---|
| `-R` | 递归 | ✅ |
| `-H` / `-L` / `-P` | 符号链接跟随策略 | ⚠️ 需映射到 reparse point 处理 |
| `-m entries` | 合并条目 | ✅ |
| `-M file` | 从文件合并 | ✅ |
| `-x entries\|position` | 删除条目 / 按序号删除 | ✅ |
| `-X file` | 从文件删除 | ✅ |
| `-a position entries` | 按位置插入 | ✅（NFSv4 语义） |
| `-b` | 删除扩展条目（保留基础） | ⚠️ 语义需重定义，见 §4.6 |
| `-d` | 操作 default ACL | ❌ Windows 无此概念 → 报错 |
| `-k` | 删除 default ACL | ❌ 同上 |
| `-n` | 不重算 mask | ❌ 无 POSIX mask → 接受但忽略 |
| `-h` | 操作符号链接本身 | ⚠️ |
| `-q` | 省略 `# file:` 头 | ✅ |
| `-i` | 条目末尾附数字 ID | ✅ |
| `-n`（getfacl） | 数值显示 | ✅ |
| `-s` | 跳过 trivial ACL | ⚠️ 需定义"trivial" |
| `-v` | verbose 掩码/标志 | ✅ |

---

## 3. 合并算法（Windows 版伪码）

FreeBSD 版本直接改内存 ACL；Windows 版必须处理"继承 ACE 只读"和"规范顺序"。

```
fn merge(desired: &[Ace], existing: &mut Dacl, filename) -> Result<()> {
    // 1. 只允许修改显式 ACE；继承 ACE 原样保留在尾部
    let (mut explicit, inherited) = existing.split_inherited();

    for new_ace in desired {
        // 2. 匹配键：SID + AceType（allow/deny）。
        //    注意：不匹配 AceFlags —— 与 FreeBSD 一致，标志随新条目覆盖。
        match explicit.iter_mut().find(|e| e.sid == new_ace.sid
                                      && e.ace_type == new_ace.ace_type) {
            Some(old) => {
                // 3. 覆盖掩码与标志（保留原有的 OBJECT_INHERIT 等由新条目决定）
                old.mask  = new_ace.mask;
                old.flags = new_ace.flags & !INHERITED_ACE;  // 不能自封"继承"
            }
            None => {
                // 4. 前置插入到显式区段
                explicit.insert(0, new_ace.with_flag(INHERITED_ACE, false));
            }
        }
    }

    // 5. 规范化：显式区段内 deny 在前、allow 在后（Windows 要求）
    explicit.sort_by_key(|e| e.ace_type != ACCESS_DENIED);

    // 6. 重组：显式 + 继承
    *existing = Dacl::from(explicit, inherited);
}
```

**与 FreeBSD 的三处差异：**

| 点 | FreeBSD | Windows |
|---|---|---|
| 匹配范围 | 全 ACL | **只匹配显式 ACE**（继承 ACE 不可改） |
| 插入位置 | 绝对位置 0 | 显式区段内，且满足 deny-before-allow |
| 标志处理 | 直接复制 flagset | 必须清除 `INHERITED_ACE` 位 |

---

## 4. Windows 必须偏离的 6 点

### 4.1 继承 ACE 不可就地修改（实测已验证）

Windows 里带 `INHERITED_ACE` 标志的 ACE 不能被就地修改或删除。想改变继承来的权限，只有三条路：

1. 改父目录的 ACL 并让其传播；
2. 给对象设 `SE_DACL_PROTECTED`（断开继承），再手工重建；
3. 新增一条同 SID 的**显式** ACE 覆盖效果（依赖求值顺序，见下）。

**FreeBSD 没有这个限制**（NFSv4 ACL 的每个条目都可写）。

#### 实测记录（2026-11-06，Windows 11 + icacls）

| 操作 | 实际行为 |
|---|---|
| `icacls f.txt /remove *S-1-5-18` | 输出"已成功处理 1 个文件"，**但继承 ACE 原样保留** |
| `icacls f.txt /grant *S-1-5-18:(R)` | 不修改继承 ACE，**新增一条显式** `SYSTEM:(R)` |

结果 DACL 同时含两条同 SID 条目：

```
f.txt NT AUTHORITY\SYSTEM:(R)          ← 新增的显式 ACE
      NT AUTHORITY\SYSTEM:(I)(F)       ← 原有的继承 ACE
      BUILTIN\Administrators:(I)(F)
      ZNIE-PC\znie:(I)(F)
```

**两个结论：**

1. **`icacls` 的静默失败是真的**——删除继承 ACE 返回成功但无效果。我们的 `setfacl -x` 必须报明确错误（`拒绝：该条目由父目录继承，请修改父目录或使用 --protect`），不能照抄这种行为。
2. **同一 SID 可同时存在显式与继承条目**，因此合并的匹配键必须限定在**显式 ACE 范围内**，否则会匹配错条目。这印证了 §3 伪码里 `split_inherited()` 的必要性，也回答了 §8 待验证项 #1。

### 4.2 规范顺序（canonical order）

Windows 要求：
- 所有显式 ACE 在继承 ACE 之前；
- 显式区段内 deny 在 allow 之前。

**两条都已实测确认**（2026-11-06）：

```
sub Everyone:(DENY)(W)                 ← 新增 deny，排到最前
    BUILTIN\Users:(OI)(CI)(RX)          ← 显式 allow，在 deny 之后
    NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)  ← 继承条目全部在后
```

FreeBSD 的"插入到位置 0"策略直接搬过来会产生非法 DACL。必须在插入后重排（见 §3 第 5 步），或用 `SetEntriesInAclW` 让系统做合并。

### 4.3 `owner@` 语义差异

映射到 Owner Rights SID（`S-1-3-4`）。但 Windows 中**对象 owner 恒定拥有 `READ_CONTROL | WRITE_DAC`**（隐式授予，无法通过 DACL deny）。NFSv4 里 `owner@` 是可以被 deny 的。

**必须在文档里写明此差异**，否则用户从 FreeBSD 迁移过来会踩坑。

### 4.4 无 POSIX mask

`-n`（不重算 mask）在 Windows 上无意义。建议：接受该选项但忽略，不报错（保持脚本兼容）。

### 4.5 无 default ACL

`-d` / `-k` 在 Windows 无对应概念。行为对齐 FreeBSD 对 NFSv4 的处理方式——报错而非静默忽略：

```
warnx("%s: there are no default entries in NFSv4 ACLs", path)
```

### 4.6 `-b`（删除扩展条目）语义需重定义

FreeBSD 的 `-b` 调用 `acl_strip_np(prev_acl, !n_flag)`，剥离到只剩基础条目。

Windows 上建议定义为：**删除所有显式 ACE，保留继承 ACE**（等价于"恢复为纯继承状态"）。这更符合 Windows 管理员的心智模型。需要在 `--help` 里明确说明。

---

## 5. 输出格式（照搬 getfacl.c）

```c
if (!qflag)
    printf("# file: %s\n# owner: %s\n# group: %s\n", path, uname, gname);
```

- 多文件之间用**空行**分隔（`more_than_one` 计数器）；
- 头部三行固定；
- 条目由 `acl_to_text_np` 生成，我们自行实现等价输出：

```
            owner@:rwxp--aARWcCos:-------:allow
            group@:r-x---a-R-c--s:-------:allow
         everyone@:r-x---a-R-c--s:-------:allow
```

字段宽度对齐（FreeBSD 用右对齐到固定宽度），`-v` 时展开为长名形式。

**owner/group 行**：Windows 对应 `GetNamedSecurityInfo` 返回的 Owner SID 和 Primary Group SID，需 `LookupAccountSid` 转成 `DOMAIN\name`。

---

## 6. 映射表汇总

### 6.1 tag → trustee

| NFSv4 tag | Windows trustee |
|---|---|
| `owner@` | Owner Rights SID `S-1-3-4` |
| `group@` | 对象 Primary Group SID |
| `everyone@` | `S-1-1-0` |
| `user:NAME` | `LookupAccountNameW(NAME)` |
| `group:NAME` | `LookupAccountNameW(NAME)` |

### 6.2 permissions → access mask

见 DESIGN.md §D1 的 14 项表（`r/w/p/x/d/D/a/A/R/W/c/C/o/s`）。

集合：`read_set` / `write_set` / `modify_set` / `full_set`。

### 6.3 inheritance flags → ACE flags

| NFSv4 | Windows |
|---|---|
| `f` | `OBJECT_INHERIT_ACE` |
| `d` | `CONTAINER_INHERIT_ACE` |
| `i` | `INHERIT_ONLY_ACE` |
| `n` | `NO_PROPAGATE_INHERIT_ACE` |
| `I` | `INHERITED_ACE` |

### 6.4 entry type

| NFSv4 | Windows |
|---|---|
| `allow` | `ACCESS_ALLOWED_ACE_TYPE` |
| `deny` | `ACCESS_DENIED_ACE_TYPE` |

---

## 7. 源码清单与获取状态

| 文件 | 状态 | 用途 |
|---|---|---|
| `bin/setfacl/setfacl.1` | ✅ | CLI 规格 |
| `bin/setfacl/getfacl.1` | ✅ | CLI 规格 |
| `bin/setfacl/setfacl.c` | ✅ | 操作队列、递归、主流程 |
| `bin/setfacl/merge.c` | ✅ | 合并/插入算法 |
| `bin/setfacl/remove.c` | ✅ | 删除语义 |
| `bin/setfacl/util.c` | ✅ | 品牌判定 |
| `bin/setfacl/setfacl.h` | ✅ | 模块划分 |
| `bin/setfacl/files.c` | ❌ 404 | `get_acl_from_file()`；语义由 man page 定义（一行一条、`#` 注释），自行实现 |
| `bin/getfacl/getfacl.c` | ✅ | 输出格式 |
| `bin/setfacl/mask.c` | ⬜ 未取 | POSIX mask 重算，Windows 不需要 |

---

## 8. 待验证项（实现时确认）

1. ~~Windows DACL 中同一 SID + 同类型存在多条 ACE 时 `-m` 匹配哪一条？~~
   **已回答**：同一 SID 的显式与继承 ACE 可以共存（实测）。匹配范围限定在显式 ACE 内，取第一条匹配项。
2. `-b` 的"删除所有显式 ACE"在对象无继承 ACE 时会导致空 DACL——空 DACL 表示"拒绝所有人"，语义危险。必须特殊处理（保留至少 owner 的完全控制，或报错）。
3. `SE_DACL_PROTECTED` 场景下 `-R` 的行为：子对象不再继承，递归语义会改变。
4. `-v` verbose 格式的确切列宽，需以 FreeBSD 实机输出为准（可用其 man page 示例反推）。
