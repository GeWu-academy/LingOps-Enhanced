# 13 团队 & 设置

## 一、团队（`/team`）

当前 v0.2 版本是**占位页面**：

```
团队管理
团队信息、成员管理等功能正在开发中...
```

后端已有 `/api/v1/users` 接口（用户列表、创建、删除），但前端未接。需要多用户时可直接调 API：

> 扩展版曾有「团队作战室」（侧边栏「团队」+ 12801 `/api/team` + `data/team.db`），**v1.3.2 已整体移除**。
> 单人 AWD 用不上，且它要额外维护一个 SQLite 库和一层后端路由。现在侧边栏只剩「端口扫描」和「ARTEX」。



```bash
# 列表
curl -H "Authorization: Bearer $TOKEN" http://localhost:12800/api/v1/users

# 新建
curl -X POST http://localhost:12800/api/v1/users \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"username":"player2","password":"Passw0rd!","role":"operator"}'
```

> 角色、权限粒度以后端实现为准；比赛单人作战时无需关心。

---

## 二、系统设置（`/settings`）

页面标题「系统设置」，副标题「修改密码等系统配置」，最大宽度 600px，只有两块内容。

### 2.1 账户信息

```
用户名：admin （用户名不可修改）
```

用户名取自登录后 localStorage 的 `lingops_user`，不可在此修改。

### 2.2 修改密码

| 字段 | 必填 | 规则 |
|---|---|---|
| 原密码 `old_password` | ✅ | 当前登录密码 |
| 新密码 `new_password` | ✅ | 至少 6 位 |
| 确认新密码 `confirm_password` | ✅ | 必须与新密码一致 |

点「确认修改」→ `POST /api/v1/auth/change-password`。

- 成功：弹窗「密码修改成功 / 密码已修改，请使用新密码重新登录」，点「重新登录」清除 token 跳 `/login`；
- 失败：右上角红字提示后端 message（常见：原密码错误）。

**注意**：改密后所有旧 token 可能失效，其他浏览器/标签页需重新登录。

### 2.3 忘记密码怎么办

没有「找回密码」入口。直接改数据库（默认 `admin123` 的 bcrypt 哈希）：

```bash
cd /Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64
# 先停服务
sqlite3 data/lingops.db "select id,username,password from users;"
# 用已知哈希替换（示例为 admin123 的 bcrypt）
sqlite3 data/lingops.db "update users set password='<bcrypt-hash>' where username='admin';"
```

更简单：删掉 `data/lingops.db` 重启，会重新初始化并生成 `admin/admin123`（**会丢失所有数据**）。

### 2.4 账号安全建议

- 比赛环境把默认密码改掉（尤其机器暴露在公网/队友网段）；
- JWT secret 在 `configs/config.yaml` 的 `jwt.secret`，默认 `change-me`，公网部署必须改，否则可伪造 token；
- 不要多人共用 admin，操作记录无法区分。
