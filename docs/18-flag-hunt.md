# 18 · Flag 查找（扩展模块）

> 本模块是**前端注入扩展**，不改动官方二进制。官方 `/flag` 页面只能「手工填一个固定路径 + 定时读」，本扩展补上了**自动发现**能力：在你已经拿到的 WebShell 上搜索 flag 文件、提取 flag 值、一键转成官方监控任务。

---

## 一、为什么官方 Flag 页面不够用

官方 `/flag` 页面（[10 Flag 读取](10-flag.md)）只有一张表单：

| 字段 | 说明 |
|---|---|
| 选择 WebShell | 挑一个已添加的壳 |
| Flag 路径 | **默认 `/flag`，只能手填一个固定路径** |
| 读取间隔 | 默认 30s |

它做的是「定时 `file_get_contents(路径)`」，因此：

- 路径写错 → 一直失败，任务列表里只显示「失败」；
- 不知道 flag 在哪 → 只能靠猜；
- 目标机是 Windows（`D:\flag.txt`）还是 Linux（`/flag`）→ 要自己判断；
- 想看站点目录里有没有藏 flag → 没有搜索功能。

实际比赛里 flag 可能叫 `flag.php`、`x_flag.txt`、`flag.jpg`、`flags/` 目录下任意名字，位置可能是 `/flag`、`/root/flag`、站点根目录、甚至 `/tmp`。手工猜基本靠运气。

本扩展解决的就是这一步：**先把候选路径搜出来，再让你挑**。

---

## 二、入口

刷新页面（`Cmd + Shift + R`）后有两个入口：

1. **侧边栏**：第一个菜单项后面多出「**Flag 查找**」（带 🔍）；
2. **官方 Flag 页面**：`/flag` 右上角「刷新列表」按钮右侧多出「**🔍 查找 Flag**」按钮。

两个入口打开的是同一个全屏面板。

---

## 三、界面说明

```
┌──────────────────────────────────────────────────────────────┐
│ 🔍 Flag 查找                                           [×]   │
├──────────────────────────────────────────────────────────────┤
│ WebShell [mock-linux ▾]  模式 [快速 ▾]  关键词 [flag]        │
│ ☐ 同时搜文件内容   ☐ 宽松匹配   ☐ 只看含 Flag    [开始] [停止]│
│ 直接读取 [ /var/www/html/flag.php          ] [读取]          │
├──────────────────────────────────────────────────────────────┤
│ 就绪                                  ▓▓▓▓▓░░░░░  12/49       │
├──────────────────────────────────────────────────────────────┤
│ 路径                        │ 类型 │ Flag / 摘要      │ 操作  │
│ /www/flag.php               │ 文件 │ flag{abc123}    │ 监控 查看│
│ /www/sub/x_flag.txt         │ 文件 │ flag{deep_7788} │ 监控 查看│
│ /opt/gflags_completions.sh  │ 文件 │ #!/bin/bash ...  │ 监控 查看│
│ /www/flag                   │ 不可读│ 不存在/无权限    │      │
├──────────────────────────────────────────────────────────────┤
│ 共 49 个候选 · 可读 44 · 含 Flag 2      [全部加入监控] [复制路径]│
└──────────────────────────────────────────────────────────────┘
```

### 控件

| 控件 | 作用 |
|---|---|
| **WebShell** | 选一个已添加的壳（必须先在 [03 Shell 管理](03-shells.md) 里添加并测试连通） |
| **模式** | 见下一节，决定搜索的激进程度 |
| **关键词** | 默认 `flag`，文件名包含它就命中；可改成 `key`、`secret`、`答案` 等 |
| **同时搜文件内容** | 额外跑 `grep -rIl "flag{"`（Linux）/ `findstr`（Windows），**慢**，只在快速模式没结果时用 |
| **宽松匹配** | 提取正则从 `flag{...}` 放宽到 `任意前缀{...}`，例如 `ctf{...}`、`DASCTF{...}`、`FLAG_xxx` |
| **只看含 Flag** | 结果表只显示命中行，隐藏目录/不可读项 |
| **直接读取** | 已知路径时跳过搜索，直接读并提取 |
| **开始 / 停止** | 停止会中断当前阶段（已发出的单个请求不可取消，最多等 60s 超时） |

### 结果表

- **排序**：命中 Flag > 可读文件 > 目录/不可读，命中永远在最上面；
- **类型**：`文件` / `目录` / `不可读`；
- **Flag / 摘要**：命中时显示提取到的 flag（可点「查看」看原文）；未命中显示内容前 80 字符；
- **操作**：
  - **加入监控** → 调官方 `POST /api/v1/flag/tasks`，把这个路径变成一个定时任务，按钮变「已加入 ✓」；
  - **查看** → 弹出内容预览（最多 5000 字符）。

底部：

- **全部加入监控**：把所有「可读文件」串行提交成任务（每个之间隔一点时间，避免打爆后端）；
- **复制所有路径**：把结果路径按行复制到剪贴板，方便粘到别处。

---

## 四、三种模式

| 模式 | 做什么 | 耗时（典型） | 适用 |
|---|---|---|---|
| **快速** `quick` | ① 探测 OS 与站点根 ② 试读 ~15 个常见路径（`/flag`、`/flag.txt`、`/root/flag`、`/var/www/html/flag.php`、`C:\flag.txt`…） ③ 跑一条「找文件名含关键词」的命令（深度 3 层） | 10~30s | **首选**，90% 的题够用 |
| **标准** `standard` | 快速的全部 + 目录枚举 + 每个命中文件都读一遍 | 30~90s | 快速模式找到路径但没提取到内容 |
| **深度** `deep` | 全盘搜索（Windows 用 PowerShell `Get-ChildItem -Recurse`，Linux 用 `find /`），可选搜文件内容 | 1~10 分钟 | 前面都没结果、怀疑 flag 藏在奇怪位置 |

> 搜索深度大时目标机 IO 会很重，**AWD 比赛里别对别人的机器跑深度模式**，容易被 OOM/超时判死。

---

## 五、原理

全部基于两个已有的 WebShell 接口，没有新协议：

```http
POST /api/v1/shells/{id}/ws/exec
{"command": "find /var/www -maxdepth 3 -iname \"*flag*\""}
→ {"code":0,"data":{"output":"/var/www/html/flag.php\n..."}}

GET /api/v1/shells/{id}/ws/read?path=/var/www/html/flag.php
→ {"code":0,"data":{"content":"flag{abc123}"}}
```

流程：

1. **探测环境**：`pwd`（Linux）/ `cd`（Windows，输出当前目录），据此判断 OS 与站点根；
2. **试读常见路径**：并发上限 4，逐个 `ws/read`，成功（`content` 非空且不是 PHP 报错文本）就进候选；
3. **执行搜索命令**：按 OS 拼命令（见下表），把输出的每行当候选路径；
4. **读取候选**：`MAX_READ = 120`，超出的只列路径不读；
5. **提取 flag**：正则匹配，命中的置顶；
6. **可选**：提交为官方监控任务。

### 各平台命令差异

| 目的 | Linux | Windows |
|---|---|---|
| 找文件名 | `find <root> -maxdepth 3 -iname "*flag*"` | `dir /s /b <root>\*flag*` |
| 列目录名 | `ls -d /flag* /root/flag* ...` | `for /d %i in (...) do @echo %i` |
| 找内容 | `grep -rIl "flag{" <root>` | `findstr /s /i /m "flag{" <root>\*` |
| 全盘 | `find / -iname "*flag*" 2>/dev/null` | `powershell -c "Get-ChildItem C:\ -Filter *flag* -Recurse -EA 0 \| % FullName"` |

### 判定「读到了」的坑

`ws/read` 有个特性：**文件不存在时 `code` 仍然是 0，`content` 是空串**。如果目标 `display_errors` 开着，还会把 `Warning: file_get_contents(...): failed to open stream` 当内容返回。

所以扩展的成功判据是：

```js
content 非空 && 内容不匹配 /No such file|failed to open stream|Permission denied|__LP_READ_FAIL__/
```

只判断 `code === 0` 会把「不存在」当成「读到了空文件」，候选表会被垃圾填满。

---

## 六、正则

| 模式 | 正则 | 命中示例 |
|---|---|---|
| 默认 | `flag\{[^}\r\n]{1,200}\}` | `flag{abc_123}`、`FLAG{x}`（大小写不敏感时） |
| 宽松 | 额外加 `[A-Za-z][A-Za-z0-9_]{1,15}\{[A-Za-z0-9_+\-/=]{6,}\}` | `ctf{...}`、`DASCTF{...}`、`NSSCTF{...}` |

宽松模式可能误报（比如 CSS `@media{...}`、代码里的 `foo{bar}`），所以默认关闭。

---

## 七、常见问题

**Q：点「开始」一直转，没结果？**
目标壳可能离线。先到 [03 Shell 管理](03-shells.md) 点「测试」，状态不是 `online` 就先修连通性。扩展对单个请求设了 60s 超时，超时会跳过该阶段。

**Q：候选一大堆，但都没 flag？**
说明 flag 不在文件名里。勾上「同时搜文件内容」+ 用「深度」模式；或者先把「只看含 Flag」勾上确认确实是 0 命中。

**Q：读文件全是「不可读」？**
一句话木马的进程用户权限不够（比如 `www-data` 读不了 `/root/flag`）。要么换权限更高的壳（`/tmp` 提权、SSH），要么让文件可读：`chmod 644 /path`。

**Q：Windows 上路径乱码 / 全是 UNC？**
`ws/read` 的 `path` 是**相对一句话所在目录**解析的，传 `/` 会变成 `\\server\share`。扩展对 Windows 会自动拼盘符（`C:\`、`D:\`），不要手动填 `/` 开头的路径。

**Q：找到了 flag，但官方页面还是显示失败？**
扩展只是把路径提交成任务，任务本身由官方后台定时执行。提交后点官方「刷新列表」看状态；失败通常是路径写错或壳掉线。

**Q：升级了 LingOps，扩展没了？**
官方升级会覆盖 `frontend/dist`。重新注入即可（见下一节）。

---

## 八、安装 / 维护

扩展文件位置：

```
frontend/dist/assets_v2/lp-ext/flaghunt.js    # 本扩展
frontend/dist/assets_v2/lp-ext/boot.js        # 注入器，动态加载 flaghunt.js
frontend/dist/index.html                      # 引用 boot.js?v=N
```

`boot.js` 里加载逻辑：

```js
if (!window.__lpFlagHunt) {
  var fh = document.createElement('script');
  fh.src = '/assets_v2/lp-ext/flaghunt.js?v=3';
  fh.id = 'lp-ext-flaghunt';
  document.head.appendChild(fh);
}
```

**改完必须 bump 版本号**（前端静态文件没走 hash，浏览器会缓存）：

1. `boot.js` 里 `flaghunt.js?v=3` → `v=4`；
2. `index.html` 里 `boot.js?v=7` → `v=8`；
3. 浏览器 `Cmd + Shift + R` 硬刷新。

**卸载**：删掉 `flaghunt.js`，并把 `boot.js` 里那段加载代码注释掉，然后 bump 版本。

---

## 九、调试

浏览器控制台：

```js
window.__lpFlagHunt            // true 表示脚本已加载
window.__lpFlagHuntOpen()      // 强制打开面板
window.__lpFlagHuntState       // 当前状态：{shells, shellId, running, rows, os, webroot}
window.__lpFlagHuntState.rows  // 结果数组，含 path/kind/content/flags
```

手动验证接口是否通：

```bash
TOKEN=你的token
curl -s -X POST http://127.0.0.1:12800/api/v1/shells/1/ws/exec \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"command":"find /var/www -maxdepth 3 -iname \"*flag*\""}'

curl -s "http://127.0.0.1:12800/api/v1/shells/1/ws/read?path=/var/www/html/flag.php" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 十、和官方 Flag 页面的配合

推荐流程：

1. 侧边栏「Flag 查找」→ 选壳 → **快速** 模式 → 开始；
2. 命中行点「**加入监控**」（间隔默认 30s）；
3. 切到官方 `/flag` 页面 → 「刷新列表」→ 看到新任务 → 等一轮读取；
4. 官方页面「详情」里能看「最新 Flag」，还能复制；
5. 如果 flag 会变（AWD 常见），监控任务会自动刷新，比手抄省事。

> 官方「成绩统计」（`/flag/stats`）只统计**通过官方规则**提交的 flag，扩展找到的 flag 不会自动算分，需要你按比赛要求手动提交到计分平台。
