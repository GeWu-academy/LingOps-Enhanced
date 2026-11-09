# 07 WAF 管理

**入口**：左侧菜单「防御」→「WAF 管理」→ `/defense/waf`
**接口**：`GET /api/v1/waf/templates`、`POST /api/v1/waf/deploy`、`POST /api/v1/waf/:id/check`、`POST /api/v1/waf/:id/uninstall`

通过已登记的 **SSH 资产**，把一份 PHP 软 WAF 文件写到网站根目录，并用 `.user.ini` 的 `auto_prepend_file` 让**每个 PHP 请求都先加载 WAF**。适合 AWD 中快速给整站加一层拦截。

---

## 1. 三种 WAF 模板

| type | 名称 | 说明 |
|---|---|---|
| `waf1` | **通防WAF** | 完整的类封装 WAF，包含日志记录、SQL 注入/文件包含/命令执行检测、上传拦截，适合全面防护 |
| `waf2` | **简易WAF** | 轻量级函数式 WAF，检测并过滤危险字符，对网站性能影响小 |
| `waf_log` | **日志WAF** | 详细日志记录 WAF，保存所有请求和上传文件，适合取证分析和流量监控 |

选择建议：

- 开局先上 `waf2`（快、影响小），确认网站正常；
- 需要拦上传/命令执行时换 `waf1`；
- 怀疑已被打、要分析对手 payload 时用 `waf_log`。

---

## 2. 前置条件

1. 「Shell 管理」里有**在线的 SSH 资产**（WebShell 不能部署 WAF）；
2. 目标 Web 服务是 **PHP-FPM / FastCGI**（`.user.ini` 才会生效）；
3. SSH 用户对 Web 根目录有写权限（通常需要 root 或 www-data）；
4. 知道真实 Web 根目录（`/var/www/html`、`/www/wwwroot/xxx`、`/usr/share/nginx/html` 等）。

> Apache + `mod_php` 不读取 `.user.ini`，部署后不会生效。这种环境需要改 `php.ini` 的 `auto_prepend_file` 或 httpd.conf 的 `php_value`。

---

## 3. 部署步骤

1. 打开「WAF 管理」页；
2. 顶部表单：

| 字段 | 说明 | 默认 |
|---|---|---|
| SSH 会话 | 选择在线的 SSH 资产 | — |
| WAF 类型 | 通防 / 简易 / 日志 | — |
| Web 根目录 | 网站真实根目录 | `/var/www/html` |
| WAF 文件名 | 落地文件名 | `waf.php` |

3. 点 **部署 WAF**；
4. 成功后弹窗显示：SSH 会话、WAF 类型、WAF 文件路径、`.user.ini` 路径等；
5. 「已部署的 WAF」列表新增一条记录，状态为「运行中」（`active`）。

### 平台做了什么

```
写入 <web_root>/<waf_filename>          # WAF 代码
写入/追加 <web_root>/.user.ini          # auto_prepend_file = <web_root>/<waf_filename>
```

之后每个 PHP 请求都会先执行 WAF，再执行原业务代码。攻击日志默认写到 `/tmp/waf_attack.txt`（以模板实现为准）。

---

## 4. 已部署列表

列：SSH 会话、WAF 类型、Web 根目录、WAF 文件、状态、部署时间、操作。

| 操作 | 说明 |
|---|---|
| **检查状态** | 通过 SSH 验证 WAF 文件与 `.user.ini` 是否存在且配置正确；进度弹窗逐条显示「建立 SSH 连接 → 验证 WAF 文件与 .user.ini → 运行正常/失败原因」 |
| **卸载** | 删除 WAF 文件并清理 `.user.ini` 中的 `auto_prepend_file` 配置 |

状态只有三种：**运行中**（`active`，绿）、**已失效**（`inactive`，红）、**未知**（`unknown`，灰）。检查失败时先看错误信息，再决定是否重部署。

---

## 5. 验证 WAF 是否生效

在 SSH 终端里：

```bash
# 1. 文件是否存在
ls -l /var/www/html/waf.php /var/www/html/.user.ini

# 2. .user.ini 内容
cat /var/www/html/.user.ini
# 应包含：auto_prepend_file=/var/www/html/waf.php

# 3. 触发一条攻击特征，看是否被拦
curl -s "http://127.0.0.1/?id=1' UNION SELECT 1,2,3-- -"

# 4. 看日志
tail -f /tmp/waf_attack.txt
```

浏览器访问站点首页，确认**没有 500**、页面内容正常。

---

## 6. 风险与回滚

WAF 是「全局前置脚本」，一旦语法错误或规则过严，**整站会 500**。所以：

1. 部署前先用「基线管理 → backup」备份网站；
2. 部署后立刻访问首页 + 一个业务功能验证；
3. 出问题立即在列表点「卸载」，或 SSH 手动：
   ```bash
   rm -f /var/www/html/waf.php
   sed -i '/auto_prepend_file/d' /var/www/html/.user.ini
   ```
4. 若 `.user.ini` 有缓存（`user_ini.cache_ttl` 默认 300 秒），改完等 5 分钟或重启 PHP-FPM。

---

## 7. 常见问题

**Q：部署成功但攻击没被拦？**
A：① 不是 PHP-FPM（`.user.ini` 不生效）；② `web_root` 填错，WAF 没在真实站点目录；③ `.user.ini` 缓存未过期；④ 攻击没命中规则（换 `waf1` 或补充规则）。

**Q：网站 500 / 白屏？**
A：WAF 语法或路径问题。立即卸载；检查 `php -l waf.php`；确认 `auto_prepend_file` 用绝对路径。

**Q：提示权限不足？**
A：SSH 用户对 `web_root` 无写权限。用 root，或 `sudo chown -R www-data:www-data` 后重试（注意别把权限改坏）。

**Q：能防住所有攻击吗？**
A：不能。软 WAF 主要挡常见 SQLi/文件包含/命令执行/上传，对免杀马、逻辑漏洞、0day 无效。仍需配合「基线加固」「WebShell 扫描」「文件监控」。

**Q：多个站点怎么办？**
A：每个站点单独部署一次（选同一 SSH，填不同 `web_root`）。列表会分别记录。
