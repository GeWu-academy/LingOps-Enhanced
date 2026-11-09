# 03 Shell 管理

**入口**：左侧菜单「攻击」→「Shell 管理」→ `/attack/shells`
**核心接口**：`/api/v1/shells`、`/shells/:id/test`、`/shells/:id/execute`、`WS /api/v1/ws/terminal/:id`、`WS /api/v1/ws/shell/:id`、`/api/v1/sftp/:id/*`

Shell 管理是整个平台的中枢：**侦察之后所有「打点」结果都在这里登记**，后续的权限维持、WAF 部署、基线加固、Flag 读取、数据库运维都依赖这里的资产。

---

## 1. 两种 Shell 类型

| 类型 | 适用场景 | 必填字段 | 能力 |
|---|---|---|---|
| **WebShell** | 通过漏洞上传/写入的 PHP 一句话 | 名称、URL、连接密码 | 命令执行、文件管理（读写/上传/下载/删除/重命名） |
| **SSH** | 拿到主机账号密码 | 名称、主机、端口、用户名、密码 | 完整交互式终端、SFTP 文件管理；WAF/基线/数据库等功能只认 SSH |

> WebShell **只支持 PHP**（语言字段固定 `php`），密码即一句话的连接密码（如 `$_POST['cmd']` 中的 `cmd` 对应的值）。

---

## 2. 添加 Shell

点击左上角 **添加 Shell**：

1. 选择「类型」：WebShell / SSH；
2. 填写对应字段：

**WebShell**

| 字段 | 说明 | 示例 |
|---|---|---|
| 名称 | 便于识别的备注 | `team3-web-80` |
| URL | 一句话完整地址，必须是 LingOps 能访问到的 | `http://192.168.1.10/shell.php` |
| 语言 | 固定 `php` | `php` |
| 密码 | 一句话连接密码 | `cmd` |

**SSH**

| 字段 | 说明 | 示例 |
|---|---|---|
| 名称 | 备注 | `team3-ssh` |
| 主机 | IP 或域名 | `192.168.1.10` |
| 端口 | 默认 22 | `22` |
| 用户名 | 登录用户 | `root` |
| 密码 | 密码登录时填写（界面**没有**私钥输入框） | `********` |

> v0.2 的 SSH 只支持密码认证，且创建时密码必填；需要密钥登录时请先给目标配置密码或改后端。

3. 确定保存。

---

## 3. 列表与批量操作

列表列：名称、类型、目标（WebShell 显示 URL，SSH 显示 `user@host:port`）、状态、操作。

| 状态 | 含义 |
|---|---|
| 在线（绿） | 最近一次测试连接成功 |
| 离线（红） | 连接失败/超时 |
| 未知（灰） | 刚添加还没测试过 |

操作列：

- **测试连接**：发起一次真实连接，弹窗显示进度和「连接成功 / 连接失败 - 原因」，并更新状态；
- **编辑**：修改地址/密码等（密码显示为掩码，不改则保持原值）；
- **打开终端**：WebShell 打开「WebShell 终端」，SSH 打开「SSH 终端」；
- **文件管理**：打开文件管理器；
- **删除**：单条删除。

顶部按钮：

- **WebShell 扫描**：跳转到防御模块的源码查杀页；
- **批量测试**：对勾选的 Shell 逐个测试，弹窗显示进度与逐条结果（成功/失败原因），结束后自动刷新状态；
- **批量删除**：并发删除选中项。

---

## 4. WebShell 终端

点击「打开终端」后是一个模拟终端（xterm.js）：

- 打开时自动执行 `echo CONNECTION_TEST` 做连通性检查，显示 `✓ 连接成功` 或失败原因；
- 输入命令回车执行，通过 `POST /api/v1/shells/:id/execute` 转发；
- 支持 `cd`：会记录当前目录，后续命令自动 `cd <dir> && <cmd>`；
- 输出为空时提示 `(无输出)`；错误以红色显示；
- 这是**命令级终端**，不是真正的 PTY：`vim`、`top` 这类全屏交互程序不可用，请改用 SSH。

WebShell 文件管理（右侧抽屉）：

- 目录浏览、进入上级；
- 查看/编辑文本文件；
- 上传文件、下载文件、下载目录（打包）；
- 新建文件（touch）、新建目录（mkdir）、重命名、删除。

对应接口：`/api/v1/shells/:id/ws/files|read|exec|write|delete|mkdir|rename|touch`。

---

## 5. SSH 终端

SSH 终端是真正的交互式 PTY（WebSocket `/api/v1/ws/terminal/:id`），支持：

- `vim`、`top`、`htop` 等全屏程序；
- `sudo -i` 提权后的持续会话；
- 窗口大小自适应；
- 顶部「终端 / 文件管理」切换。

文件管理走 SFTP（`/api/v1/sftp/:id/list|read|write|create|delete|rename|download`），能力与 WebShell 文件管理一致，但更稳定，支持大文件下载。

---

## 6. 典型使用流程

```
侦察拿到 IP
   ↓
利用漏洞上传一句话（可用「木马生成」页生成）
   ↓
Shell 管理 → 添加 Shell → 选 WebShell → 填 URL + 密码
   ↓
点「测试连接」确认在线
   ↓
打开终端执行 id / whoami / ls -l /flag 验证权限
   ↓
（可选）用 SSH 账号添加 SSH 资产，后续加固/部署 WAF 用
   ↓
去「权限维持」投放不死马；去「Flag 读取」配置定时任务
```

---

## 7. 文件管理器（WebShell）

点列表「操作」列的**文件夹图标**打开文件管理抽屉，接口为 `/api/v1/shells/:id/ws/files?path=`。
抽屉里可以新建/上传/重命名/删除/下载/预览编辑，路径参数就是当前所在目录。

### 7.1 Windows 目标的坑（已修复）

官方 v0.2 前端把 `/` 当作初始路径和「根目录」，在 **Windows 目标**上表现为：

- 打开后列表全是 `$RECYCLE.BIN`、`Program Files`、`Users`、`Windows` 这类**盘符根内容**，不是你上传 shell 的目录；
- 所有条目都是「文件」图标，大小 `0`、权限 `0`，**双击文件夹也进不去**（只会去读文件，报「读取文件失败」）；
- 新建/上传时路径被拼成 `/名字`，直接落到盘符根。

原因：一句话把 `path=/` 拼成 `//名字`，Windows 把 `//x` 当 UNC 网络路径（`\\x`），`is_dir()` 全部失败，所以所有条目都变成「非目录」。
Linux 目标不受影响（`/` 就是根）。

**本项目已用注入补丁修复**（`frontend/dist/assets_v2/lp-ext/fsfix.js`，由 `boot.js` 自动加载，不改官方二进制）：

| 场景 | 修复后行为 |
|---|---|
| 打开文件管理 | 直接定位到 **shell 所在目录**（也就是你上传 `shell.php` 的目录，等价 `path=.`） |
| 进入文件夹 | **单击**即可进入（官方只支持双击） |
| 向上浏览 | 列表第一行固定注入一行 `..`，点它回上级（`..` → `../..` → …） |
| 面包屑「首页」 | 回到 shell 所在目录 |
| 新建/上传 | 路径为 `./名字`，落在当前目录 |
| 双击文件 | 正常预览/编辑（路径为 `./名字`，不再是 `//名字`） |

可调项：想让它默认停在盘符根，在浏览器控制台执行

```js
localStorage.lp_fs_root = 'C:';   // 默认 '.'，即 shell 所在目录
location.reload();
```

只想临时看某个目录，也可以直接调接口（把 token 换成自己的）：

```bash
T=$(curl -s -X POST http://127.0.0.1:12800/api/v1/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["token"])')

curl -s -H "Authorization: Bearer $T" \
  'http://127.0.0.1:12800/api/v1/shells/1/ws/files?path=.'      # shell 所在目录
curl -s -H "Authorization: Bearer $T" \
  'http://127.0.0.1:12800/api/v1/shells/1/ws/files?path=C:'     # C 盘根（isDir 正常）
```

---

## 8. 常见问题

**Q：测试连接失败，但浏览器访问 URL 正常？**
A：① URL 必须是 **LingOps 主机**能访问的地址，不是你的浏览器能访问就行；② 确认密码正确、一句话没有被 WAF 拦截；③ 确认一句话支持 `system`/`shell_exec` 等函数（禁用函数会导致「无法执行命令」）；④ 用 `curl` 在 LingOps 主机上验证：`curl -s -d 'cmd=id' http://target/shell.php`。

**Q：WebShell 终端能连上但命令无输出？**
A：目标禁用了命令执行函数，或一句话只回显固定内容。换用「文件管理」读文件，或换一个可用函数的一句话。

**Q：SSH 连不上？**
A：检查端口、密码、是否只允许密钥；确认 LingOps 主机到目标的 22 端口可达；`root` 登录被 `PermitRootLogin no` 禁止时换普通用户再 `sudo`。

**Q：中文输出乱码？**
A：WebShell 返回编码与终端不一致，可在命令前加 `LANG=C.UTF-8`，或改用 SSH。

**Q：为什么 WAF/基线/数据库页面选不到我的 Shell？**
A：这些功能只接受 **在线 SSH** 资产。WebShell 只能用于命令执行、文件管理、权限维持、Flag 读取。
