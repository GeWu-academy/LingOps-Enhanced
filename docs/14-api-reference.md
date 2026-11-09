# 14 API 参考

Base URL：`http://localhost:12800/api/v1`（端口以 `configs/config.yaml` 的 `server.port` 为准）
所有接口返回统一信封：

```json
{ "code": 0, "message": "success", "data": { } }
```

- `code == 0` 成功，非 0 失败（`message` 为原因）；
- 分页接口 `data = { items: [], total, page, page_size }`；`/tasks` 例外，`data` 直接是任务数组；
- 除登录/刷新外，都需要请求头 `Authorization: Bearer <token>`。

---

## 1. 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 登录，body `{username,password}` |
| POST | `/auth/refresh` | 刷新，body `{refresh_token}` |
| POST | `/auth/logout` | 注销 |
| POST | `/auth/change-password` | body `{old_password,new_password,confirm_password}` |

登录响应关键字段：`data.token`（**不是** `access_token`）、`data.refresh_token`、`data.user`。

```bash
TOKEN=$(curl -s -X POST http://localhost:12800/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["token"])')
```

---

## 2. 总览 / 任务

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/stats/dashboard` | 首页统计（Shell 在线、Flag 读取、运行任务等） |
| GET | `/tasks` | 任务列表（`page`、`page_size`、`type`、`status`） |
| POST | `/tasks` | 创建任务 |
| GET | `/tasks/:id` | 任务详情 |
| PUT | `/tasks/:id` | 更新任务 |
| DELETE | `/tasks/:id` | 删除任务 |
| POST | `/tasks/:id/cancel` | 取消任务 |
| POST | `/tasks/cleanup` | 清理已结束任务 |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:12800/api/v1/tasks?page=1&page_size=20"
```

---

## 3. 资产 / Agent / 监控

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/assets` | 主机资产列表 / 新增 |
| GET/PUT/DELETE | `/assets/:id` | 详情 / 更新 / 删除 |
| GET | `/agents` | Agent 列表 |
| GET | `/agents/:id` | Agent 详情 |
| DELETE | `/agents/:id` | 删除 Agent |
| POST | `/agents/:id/command` | 下发命令 |
| GET | `/monitor/alerts` | 告警列表 |
| PUT | `/monitor/alerts/:id/ack` | 确认告警 |
| GET | `/monitor/stats/ips` | 按 IP 统计 |
| GET | `/monitor/stats/urls` | 按 URL 统计 |
| GET | `/monitor/traffic/stats` | 流量统计 |
| GET | `/monitor/traffic/:id` | 流量详情 |
| POST | `/monitor/traffic/upload` | 上传流量日志 |
| POST | `/monitor/traffic/search` | 检索流量 |

---

## 4. 侦察

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/discovery/hosts` | 主机发现，body `{ip_range, timeout, ping_count}` |
| POST | `/discovery/ports` | 端口扫描 |
| POST | `/discovery/services` | 服务识别 |
| POST | `/discovery/cancel/:id` | 取消扫描 |
| GET | `/ws/discovery?token=&discovery_id=` | 进度 WebSocket |

```bash
curl -X POST http://localhost:12800/api/v1/discovery/hosts \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip_range":"192.168.1.10-50","timeout":500,"ping_count":1}'
```

---

## 5. Shell 管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/shells` | 列表 / 新增（webshell 或 ssh） |
| GET/PUT/DELETE | `/shells/:id` | 详情 / 更新 / 删除 |
| POST | `/shells/:id/test` | 测试单个连接 |
| POST | `/shells/:id/execute` | 执行命令 |
| POST | `/shells/batch` | 批量执行 |
| POST | `/shells/batch-test` | 批量测试 |
| POST | `/webshell/exec` | 免资产直连，body `{url,password,command}` |
| GET | `/ws/terminal/:id` | SSH 终端 WS（PTY） |
| GET | `/ws/shell/:id` | WebShell 终端 WS |

WebShell 文件管理：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/shells/:id/ws/files?path=` | 列目录 |
| GET | `/shells/:id/ws/read?path=` | 读文件 |
| POST | `/shells/:id/ws/exec` | 执行命令 |
| POST | `/shells/:id/ws/write` | 写文件 |
| POST | `/shells/:id/ws/delete` | 删除 |
| POST | `/shells/:id/ws/mkdir` | 建目录 |
| POST | `/shells/:id/ws/touch` | 建空文件 |
| POST | `/shells/:id/ws/rename` | 重命名 |

> `path` 用相对路径最稳：`.` = shell 所在目录（上传 `shell.php` 的地方）、`..` = 上级。
> **Windows 目标不要传 `/`**：后端会拼成 `//名字`，被当作 UNC 路径，`isDir` 全为 false（详见 [03 章 7.1](03-shells.md#71-windows-目标的坑已修复)）。盘符根用 `C:`。

SFTP（SSH 资产）：

| 方法 | 路径 |
|---|---|
| GET | `/sftp/:id/list` |
| GET | `/sftp/:id/read` |
| GET | `/sftp/:id/download` |
| POST | `/sftp/:id/write` |
| POST | `/sftp/:id/create` |
| POST | `/sftp/:id/delete` |
| POST | `/sftp/:id/rename` |

---

## 6. 权限维持

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/persistence` | 记录列表 |
| POST | `/persistence` | 保存记录，body `{shell_id,type,url,path,password}` |
| POST | `/persistence/:id/check` | 检查存活 |
| DELETE | `/persistence/:id` | 删除记录 |

> `/persistence/upload`、`/persistence/:id/cleanup` 前端有调用但后端未注册，会返回 SPA HTML。

---

## 7. 基线管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/baseline/actions` | 所有动作及字段定义 |
| POST | `/baseline/execute` | 执行，body `{shell_id,type,config}` |
| GET | `/baseline` | 执行历史 |
| GET | `/baseline/:id` | 详情 |
| GET | `/baseline/:id/logs` | 执行日志 |
| GET | `/baseline/:id/report` | 报告 |
| GET | `/baseline/:id/download` | 下载备份/基线文件 |
| POST | `/baseline/:id/cancel` | 取消 |
| DELETE | `/baseline/:id` | 删除记录 |

```bash
curl -X POST http://localhost:12800/api/v1/baseline/execute \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"shell_id":1,"type":"backup","config":{"target_path":"/var/www/html","backup_path":"/tmp/backups"}}'
```

---

## 8. 防御（WebShell 扫描 / WAF）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/webshell/scan` | 单文件扫描 |
| POST | `/webshell/scan-upload` | 上传扫描（multipart `file`、`language`） |
| GET | `/webshell/scan` | 扫描任务列表 |
| GET | `/webshell/scan/:job_id` | 任务详情 |
| GET | `/webshell/scan/:job_id/findings` | 命中结果 |
| GET | `/webshell/scan/:job_id/report` | 报告 |
| POST | `/webshell/scan/:job_id/cancel` | 取消 |
| DELETE | `/webshell/scan/:job_id` | 删除 |
| POST | `/webshell/download-source` | 下载源码 |
| GET | `/webshell/ssh-assets` | 可用的 SSH 资产 |
| GET | `/waf/templates` | WAF 模板 |
| POST | `/waf/deploy` | 部署，body `{shell_id,waf_type,web_root,waf_filename}` |
| GET | `/waf` | 部署记录 |
| POST | `/waf/:id/check` | 检查 |
| POST | `/waf/:id/uninstall` | 卸载 |

旧版防御接口（前端未使用）：`/defense/baselines`、`/defense/baselines/:id/scan|restore`、`/defense/harden/permissions|php|waf`。

---

## 9. 数据库管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/db/assets` | 资产列表 / 新增 |
| GET/PUT/DELETE | `/db/assets/:id` | 详情 / 更新 / 删除 |
| GET | `/db/assets/stats` | 统计 |
| POST | `/db/assets/:id/test` | 连通性测试 |
| POST | `/db/execute` | 执行 SQL，body `{asset_id,query}` |
| POST | `/db/password/change` | 改密，body `{asset_id,new_password,confirm_password}` |
| GET/POST | `/db/backups` | 备份列表 / 发起备份 |
| GET | `/db/backups/artifacts` | 备份产物 |
| POST | `/db/backups/artifacts/:id/restore` | 恢复（需 `confirm_token`） |
| GET/POST | `/db/checks` | 基线检查 |
| GET | `/db/checks/:id` | 检查详情 |
| GET | `/db/audit/logs` | 审计日志 |

```bash
curl -X POST http://localhost:12800/api/v1/db/execute \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"asset_id":1,"query":"SHOW DATABASES;"}'
```

---

## 10. Flag

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/flag/rules` | 规则列表 / 新建 |
| GET/PUT/DELETE | `/flag/rules/:id` | |
| GET/POST | `/flag/tasks` | 任务列表 / 创建 |
| GET | `/flag/tasks/:id?record_page=&record_page_size=` | 详情（含读取记录） |
| POST | `/flag/tasks/:id/stop` | 停止 |
| DELETE | `/flag/tasks/:id` | 删除 |
| POST | `/flag/collect` | 手动采集一次 |
| POST | `/flag/collect/auto` | 按规则自动采集，body `{rule_id}` |
| GET | `/flag/history` | 历史 Flag |
| GET | `/flag/scoreboard` | 积分榜 |
| GET | `/flag/stats` | 统计 |

---

## 11. AWDP

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/awdp/scan` | 源码扫描（通用接口，页面实际用 quick-scan），body `{code,language}` |
| POST | `/awdp/quick-scan` | 快速扫描（Break / Fix 页面使用） |
| POST | `/awdp/scan-upload` | 后台扫描，multipart `file`、`scan_type=break|fix|webshell`、`language` |
| POST | `/awdp/quick-scan-upload` | 快速上传扫描 |
| GET | `/awdp/scan-jobs?scan_type=` | 任务列表 |
| GET | `/awdp/scan-jobs/:id` | 详情 |
| GET | `/awdp/scan-jobs/:id/findings` | 命中 |
| GET | `/awdp/scan-jobs/:id/report` | 报告 |
| GET | `/awdp/scan-jobs/:id/source` | 源码 |
| DELETE | `/awdp/scan-jobs/:id` | 删除 |
| GET/POST | `/awdp/knowledge` | 知识列表 / 新建 |
| GET/PUT/DELETE | `/awdp/knowledge/:id` | |
| GET | `/awdp/knowledge/export` | 导出 |
| POST | `/awdp/knowledge/import` | 导入 |
| POST | `/awdp/knowledge/refresh` | 刷新内置知识 |
| GET/POST | `/awdp/scan-rules` | 规则列表 / 新建 |
| GET/PUT/DELETE | `/awdp/scan-rules/:id` | |
| GET | `/awdp/scan-rules/export` | 导出 |
| POST | `/awdp/scan-rules/import` | 导入 |
| POST | `/awdp/reset` | 重置（慎用） |
| GET/POST | `/break/payloads` | Payload 列表 / 新建 |
| PUT/DELETE | `/break/payloads/:id` | |
| GET/POST | `/break/exploits` | 利用条目 |
| PUT/DELETE | `/break/exploits/:id` | |
| GET/POST | `/break/bypasses` | 绕过条目 |
| PUT/DELETE | `/break/bypasses/:id` | |
| GET | `/break/export` | 导出 Break 知识库 |
| POST | `/break/import` | 导入 |
| GET | `/awdp/waf-templates` | WAF 模板库（49 条） |
| GET | `/awdp/waf-templates/:id` | 模板详情 |

Patch 包（UI 未接，可直接调用）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/awdp/patch/packages` | 列表 / 上传 |
| GET/PUT/DELETE | `/awdp/patch/packages/:id` | |
| GET | `/awdp/patch/packages/:id/diff` | 差异 |
| GET | `/awdp/patch/packages/:id/download` | 下载包 |
| GET | `/awdp/patch/packages/:id/download-shell` | 下载 shell |
| GET | `/awdp/patch/packages/:id/versions` | 版本列表 |
| POST | `/awdp/patch/packages/:id/rollback/:version_id` | 回滚 |
| GET | `/awdp/patch/templates` | Patch 模板 |
| POST | `/awdp/patch/generate-shell` | 生成脚本 |
| GET | `/awdp/patch-drafts` | 草稿列表 |
| POST | `/awdp/patch-drafts/batch` | 批量草稿 |
| POST | `/awdp/findings/:id/create-patch-draft` | 命中转草稿 |

---

## 12. 用户

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/users` | 列表 / 新建 |
| GET/PUT/DELETE | `/users/:id` | |

---

## 13. WebSocket

| 路径 | 用途 |
|---|---|
| `/ws/tasks` | 全局任务进度 |
| `/ws/discovery?token=&discovery_id=` | 侦察进度 |
| `/ws/terminal/:id` | SSH 交互终端（PTY） |
| `/ws/shell/:id` | WebShell 终端 |

浏览器 WS 无法自定义 Header，token 走 query 参数。示例：

```js
new WebSocket(`ws://localhost:12800/api/v1/ws/tasks?token=${token}`)
```

> 侦察页的 WS 地址在前端写死为 `http://localhost:12800`，从其他机器访问时实时进度不更新（轮询/刷新仍可用）。

---

## 14. 常见错误

| 现象 | 原因 |
|---|---|
| `401` / `code=401` | token 缺失/过期，重新登录 |
| `code=-1` + `Field validation ... required` | 缺少必填字段 |
| 返回 HTML 而不是 JSON | 路由不存在，落到了前端 SPA |
| `record not found` | ID 不存在或已删除 |
| `invalid credentials` | 用户名/密码错误 |
