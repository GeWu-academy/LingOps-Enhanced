# 08 基线管理（主机加固）

**入口**：左侧菜单「运维」→「基线管理」→ `/ops/baseline`
**接口**：`GET /api/v1/baseline/actions`、`POST /api/v1/baseline/execute`、`POST /api/v1/baseline/:id/cancel`、`GET /api/v1/baseline/:id/logs`、`GET /api/v1/baseline/:id/report`、`GET /api/v1/baseline/:id/download`

通过**在线 SSH 会话**在目标主机上执行加固操作。所有操作都是真实命令，带破坏性的（清理后门、改密码、封端口）请先看清参数。

---

## 1. 页面结构

```
使用说明（Info）
SSH 会话 [下拉]     操作类型 [下拉]
────────────────────────────────
操作说明卡（图标 + 提示 3~4 条）
动态参数表单（随操作变化）
[执行操作]
────────────────────────────────
执行历史（表格：ID/SSH 会话/操作类型/状态/开始时间/完成时间/操作）
任务详情弹窗（执行日志 / 执行结果）
```

- 「SSH 会话」只列出**在线**的 SSH 资产，并显示 `host:port`；
- 「操作类型」按 4 组分类：**备份还原、安全加固、权限管理、网络防护**；
- 选中操作后，表单自动按后端 `config_fields` 渲染并填默认值；
- 点 **执行操作** → 任务进入 `running`，弹窗实时拉日志；
- 任务详情里可 **取消任务**（运行中）、**下载报告**（仅安全巡检）、**下载备份/基线文件**（备份与文件监控）。

---

## 2. 全部 11 个操作

### 2.1 备份还原

#### 网站备份 `backup`

> 压缩备份指定目录的文件

| 字段 | 必填 | 默认 | 说明 |
|---|---|---|---|
| 备份目录 `target_path` | ✅ | `/var/www/html` | 要备份的目录 |
| 存储目录 `backup_path` | ❌ | `/tmp/backups` | 备份文件存放位置（目标机上） |
| 排除目录 `exclude_dirs` | ❌ | — | 逗号分隔，如 `vendor,node_modules,.git` |

提示：压缩为 tar.gz；支持排除大目录；备份文件保存在目标服务器上。

**用法**：开局第一件事。执行完在「执行结果」里能看到 `backup_file` 和大小，点「下载」保存到本机。

---

### 2.2 安全加固

#### 安全巡检 `audit`

> 全面检查系统安全配置和潜在风险，生成详细报告

| 字段 | 必填 | 默认 |
|---|---|---|
| Web目录 `web_root` | ❌ | `/var/www/html` |

检查内容：系统/用户/网络/进程信息、SUID/SGID 文件、计划任务、SSH 配置、最近修改文件。完成后可「下载报告」，结果页显示高/中/低危风险数量。

#### 清理后门 `clean_backdoor`

> 扫描并删除常见后门文件

| 字段 | 必填 | 默认 | 说明 |
|---|---|---|---|
| 扫描目录 `target_path` | ✅ | `/var/www/html` | |
| 仅扫描不删除 `dry_run` | ❌ | **true** | 强烈建议先保持 true |

识别：可疑扩展名（`.php.bak` 等）、单字母/数字命名的 PHP、隐藏 PHP 文件。

**正确姿势**：先 `dry_run=true` 跑一遍看列表 → 人工确认 → 再 `dry_run=false` 真删。删之前先做 `backup`。

#### MySQL改密 `mysql_passwd`

| 字段 | 必填 | 说明 |
|---|---|---|
| 原密码 `old_password` | ✅ | 用于验证 |
| 新密码 `new_password` | ✅ | 改完记得同步到「数据库管理」资产 |

> 改完密码后，网站配置文件（`config.php`、`.env`）里的密码也要同步改，否则站点挂掉。

#### 终止反弹Shell `kill_reverse`

| 字段 | 必填 | 默认 |
|---|---|---|
| 仅检测不终止 `dry_run` | ❌ | **true** |

检测 `bash -i`、`nc -e`、Python/Perl/Ruby 反连等。先检测，确认是自己的进程还是对手的，再终止。

#### 文件差异监控 `file_monitor`

> 扫描目录并记录文件哈希基线，后续可检测文件变化

| 字段 | 必填 | 默认 | 说明 |
|---|---|---|---|
| 监控目录 `target_path` | ✅ | `/var/www/html` | |
| 操作 `action` | ✅ | `create` | `create` 创建基线 / `check` 检测变化 |
| 文件类型 `extensions` | ❌ | `php,html,js,css,json` | 逗号分隔 |

**用法**：
1. 开局 `action=create` 建基线；
2. 每轮结束/怀疑被入侵时 `action=check`；
3. 结果页显示「新增/修改/删除」文件数及清单，可下载基线文件。

#### SSH改密 `ssh_passwd`

| 字段 | 必填 | 说明 |
|---|---|---|
| 新密码 `new_password` | ✅ | |
| 确认密码 `confirm_password` | ✅ | 两次一致 |

> 平台会**同步更新数据库里该 SSH 资产的密码**，下次连接自动用新密码。改完务必自己验证一次能否登录。

#### PHP安全配置 `php_secure`

> 追加安全配置到 php.ini 并重启 PHP 服务

| 字段 | 必填 | 默认 |
|---|---|---|
| 禁用函数 `disable_functions` | ❌ | `system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec,putenv` |
| open_basedir | ❌ | `/var/www/html:/tmp` |

> ⚠️ **双刃剑**：禁用函数会同时废掉你自己的 WebShell。建议只对**不需要再用马**的机器执行，或保留 `eval` 可用。`open_basedir` 填错会导致网站无法读文件，执行前备份 `php.ini`。

---

### 2.3 权限管理

#### 权限标准化 `permission`

> 设置 Web 目录权限为标准的 755/644

| 字段 | 必填 | 默认 |
|---|---|---|
| 目标目录 `target_path` | ✅ | `/var/www/html` |
| 所有者 `owner` | ❌ | — （如 `www-data:www-data`） |

目录 755、文件 644；可选 chown。适合修复对手改乱的权限。

#### 目录只读 `readonly`

> 将上传目录设为只读 (555/444)，防止文件被篡改

| 字段 | 必填 | 默认 |
|---|---|---|
| 目标目录 `target_path` | ✅ | — （如 `/var/www/html/uploads`） |
| 恢复权限 `restore` | ❌ | false |

> 设成只读后**正常上传功能会失效**。比赛里如果业务需要上传，别对 uploads 目录做；或者打完一轮再 `restore=true` 恢复。

---

### 2.4 网络防护

#### 端口封禁 `port_block`

> 使用 iptables 封禁或放行指定端口

| 字段 | 必填 | 默认 | 选项 |
|---|---|---|---|
| 端口 `port` | ✅ | — | 如 `3306`、`1-1000` |
| 操作 `action` | ✅ | `block` | 封禁 / 放行 |
| 协议 `protocol` | ❌ | `tcp` | TCP / UDP / TCP+UDP |

规则自动保存（重启后仍生效）。常见用法：封掉对手的 3306 直连、只放行自己的 IP。

> 别封 22/80，会把自己和业务一起断掉。

---

## 3. 执行历史与详情

列表：ID、SSH 会话、操作类型、状态（运行中带进度条）、开始时间、完成时间、操作（详情/下载/取消/删除）。

- 状态：`pending / running / completed / failed / cancelled`；
- 运行中的任务不能删除（勾选框禁用），可在详情里「取消任务」；
- 详情弹窗两个 Tab：
  - **执行日志**：时间 + 级别（info/success/warn/error）+ 消息，运行中自动刷新；
  - **执行结果**：按类型渲染
    - `audit`：高/中/低危数量；
    - `backup`：备份文件路径、大小、「下载」；
    - `file_monitor`：新增/修改/删除统计与清单，基线文件「下载」；
    - 其他：原始结果 JSON。

---

## 4. 推荐执行顺序（AWD 开局）

```
1. backup            备份 /var/www/html → /tmp/backups
2. audit             安全巡检，了解主机现状
3. clean_backdoor    dry_run=true 先看，再决定是否删除
4. permission        权限标准化 755/644
5. file_monitor      create 建基线
6. php_secure        （可选，确认不再需要马时）
7. port_block        （可选，封掉非必要端口）
```

每轮结束再跑一次 `file_monitor check` + `audit`，对比变化。

---

## 5. 常见问题

**Q：下拉里没有 SSH 会话？**
A：先去「Shell 管理」添加 SSH 资产并「测试连接」成功；只有在线状态才会出现在这里。

**Q：任务一直 running？**
A：目标机命令卡住（如 `tar` 大目录、`iptables` 等待锁）。看日志最后一行，必要时取消任务，SSH 手动排查。

**Q：备份下载失败？**
A：备份文件在目标机 `backup_path`，确认路径存在且有读权限；也可在「Shell 管理 → 文件管理」里直接下载。

**Q：clean_backdoor 删错了文件？**
A：从备份恢复：`tar -xzf /tmp/backups/xxx.tar.gz -C /var/www/html`。这就是为什么第一步必须备份。

**Q：php_secure 之后网站 500？**
A：`open_basedir` 限制了项目实际路径，或禁用了业务必需函数。SSH 编辑 `php.ini` 去掉对应行并重启 PHP-FPM。

**Q：iptables 规则把自己锁外面了？**
A：通过其他通道（WebShell/控制台）执行 `iptables -F`，或重启网络。别在远程会话里封 22。
