# 09 数据库管理

**入口**：左侧菜单「运维」→「数据库管理」→ `/ops/database`
**接口前缀**：`/api/v1/db`

对 MySQL 等数据库做资产管理、连通性测试、SQL 终端、整库备份和改密。资产信息（含加密后的密码）存在 LingOps 本地库里。

---

## 1. 页面结构

```
统计卡：资产总数 / 在线 / 离线
数据库资产表：[刷新] [新增资产]
  ID | 实例名称 | 类型 | 地址 | 状态 | 版本 | 操作(测试/编辑/删除/详情)
详情抽屉（右侧）
  类型 / 状态 / 版本 / 地址 / 用户名
  快捷操作：虚拟终端 / 一键备份 / 修改密码 / 测试连通性
```

初始资产列表为空，需要自己添加。

---

## 2. 新增 / 编辑资产

点「新增资产」，表单字段：

| 字段 | 必填 | 说明 |
|---|---|---|
| 实例名称 `name` | ✅ | 如 `mysql-01` |
| 数据库类型 `type` | ✅ | 发布版 UI 目前只提供 **MySQL** |
| 主机地址 `host` | ✅ | 如 `192.168.1.10` |
| 端口 `port` | ✅ | 1–65535，MySQL 默认 3306 |
| 用户名 `username` | ✅ | 如 `root` |
| 密码 `password` | ✅ | 新增必填；编辑时留空表示不修改 |
| 标签 `tags` | ❌ | 输入后回车添加，可多个 |

- 「编辑」时密码留空 = 保持原密码；
- 删除会二次确认；
- 密码在库里以 `password_enc` 加密字段存储，列表不回显。

---

## 3. 测试连通性

表格行「测试」或详情抽屉「测试连通性」：

1. 弹出进度窗，依次显示：`开始连接...` → `正在连接目标...` → `发送测试请求...` → `等待响应...` → `解析响应数据...`；
2. 成功显示「连接成功」，并把资产状态刷新为在线、回填版本号；
3. 失败显示 `连接失败 - <原因>`，常见原因：端口不通、账号密码错、MySQL 只允许 localhost、防火墙。

测试成功后状态变「在线」，未测过是「未知」。

---

## 4. 虚拟终端（执行 SQL）

详情抽屉 →「虚拟终端」→ 跳转 `/ops/database/terminal/:id`。

页面顶部：`数据库终端 · <实例名>` + `MYSQL · host:port · username`。

**快捷命令**（按类型自动切换）：

| MySQL | PostgreSQL | Redis |
|---|---|---|
| 显示数据库 `SHOW DATABASES;` | `\l` | `PING` |
| 显示表 `SHOW TABLES;` | `\dt` | `INFO` |
| 当前用户 `SELECT USER();` | `SELECT current_user;` | `KEYS *` |
| 版本信息 `SELECT VERSION();` | `SELECT version();` | `DBSIZE` |

操作：

- 输入框多行，等宽字体；
- **Ctrl + Enter** 或点「执行 (Ctrl+Enter)」执行；
- 「清空」清掉输入与结果；
- 执行结果显示：绿色标签 `执行时间 xxx ms`，若有受影响行数显示 `N 行受影响`；结果集以表格展示；
- 历史结果保留在本次会话中（刷新页面丢失）；
- 失败提示 `SQL 执行失败: <error>`，直接显示数据库原始报错，便于排错。

**典型用法**：
```sql
SHOW DATABASES;
USE ctf;                 -- 部分驱动不支持 USE，可直接写库名.表名
SELECT * FROM flag LIMIT 10;
UPDATE users SET password='x' WHERE id=1;
```
> 修改类语句没有事务保护，执行前先备份。

---

## 5. 一键备份

详情抽屉 →「一键备份」：

1. 弹出「选择要备份的数据库」，正在查询可用数据库…；
2. 单选要备份的库（查不到会显示「未找到可备份的数据库」）；
3. 点「开始备份」→ 生成后台备份任务；
4. 备份产物在 `db_backup_artifacts`，可通过 `GET /db/backups`（任务）与 `GET /db/backups/artifacts`（产物列表）获取。

恢复接口存在（`POST /db/backups/artifacts/:id/restore`），需要 `confirm_token` 二次确认，发布版 UI 未暴露入口，可用 API 调用（见 14-api-reference）。

---

## 6. 修改密码

详情抽屉 →「修改密码」：

| 字段 | 必填 | 规则 |
|---|---|---|
| 数据库名称 | — | 只读 |
| 新密码 `new_password` | ✅ | ≥ 6 字符 |
| 确认密码 `confirm_password` | ✅ | 与新密码一致 |

进度条：`正在修改密码...` → `密码修改成功！` / `密码修改失败，请重试`。成功后**同步更新资产里的密码**，后续连接用新密码。

> 改完记得同步业务配置文件（`config.php` / `.env` / `wp-config.php`），否则站点连不上库。

---

## 7. 相关接口

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/db/assets` | 资产列表（分页） |
| GET | `/db/assets/stats` | 统计：total/online/offline/unknown/at_risk/backup_ok |
| POST | `/db/assets` | 新增 |
| GET/PUT/DELETE | `/db/assets/:id` | 详情/更新/删除 |
| POST | `/db/assets/:id/test` | 连通性测试 |
| POST | `/db/execute` | 执行 SQL `{asset_id, query}` |
| POST | `/db/password/change` | 改密 `{asset_id, new_password, confirm_password}` |
| GET | `/db/backups` | 备份任务列表 |
| POST | `/db/backups` | 创建备份 |
| GET | `/db/backups/artifacts` | 备份产物列表 |
| POST | `/db/backups/artifacts/:id/restore` | 恢复备份（需 `confirm_token`） |
| GET/POST | `/db/checks` | 巡检记录列表 / 发起巡检 |
| GET | `/db/checks/:id` | 巡检详情 |
| GET | `/db/audit/logs` | 操作审计日志 |

curl 示例：

```bash
TOKEN=...   # 登录拿到的 data.token
# 新增
curl -s -X POST http://127.0.0.1:12800/api/v1/db/assets \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"mysql-01","type":"mysql","host":"192.168.1.10","port":3306,"username":"root","password":"root","tags":["web"]}'

# 执行 SQL
curl -s -X POST http://127.0.0.1:12800/api/v1/db/execute \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"asset_id":1,"query":"SHOW DATABASES;"}'
```

---

## 8. 常见问题

**Q：测试连接一直失败？**
A：① 目标 `bind-address` 只监听 127.0.0.1；② 用户没有 `%` 远程权限；③ 云安全组/iptables 未放行；④ 端口填错。可先在「Shell 管理」的 SSH 终端里 `mysql -h... -u... -p` 验证。

**Q：终端执行 `USE db;` 报错？**
A：部分驱动不返回多语句结果。改成 `SELECT * FROM db.table` 或分两次执行。

**Q：备份很慢/失败？**
A：看目标机磁盘空间与 `mysqldump` 是否存在；大库建议在目标机手动 `mysqldump` 后压缩。

**Q：改密后资产连不上？**
A：确认改的是同一个账号（如 `root@%` vs `root@localhost`），MySQL 里这是两个用户。

**Q：能管理 PostgreSQL/Redis 吗？**
A：终端快捷命令已适配 postgresql/redis 类型，但当前发布版「新增资产」下拉只提供 MySQL；其他类型需通过 API 写入后使用。
