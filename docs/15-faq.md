# 15 常见问题（FAQ）

## 一、启动

**Q1：`Config File "config" Not Found in "[/Users/xxx/configs /Users/xxx /etc/lingops]"`**

原因：程序用 viper 在 `$HOME/configs`、`$HOME`、`/etc/lingops` 找名为 `config` 的文件，不会读「当前二进制旁边的 `./configs`」——除非你 `cd` 到发布包目录。

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
./start.sh
```

或永久解决：

```bash
mkdir -p ~/configs
cp "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64/configs/config.yaml" ~/configs/config.yaml
```

**Q2：`permission denied` / `cannot be opened because the developer cannot be verified`**

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
chmod +x lingops-server start.sh
xattr -dr com.apple.quarantine lingops-server start.sh
```

**Q3：端口被占用 `bind: address already in use`**

```bash
lsof -nP -iTCP:12800 -sTCP:LISTEN
# 杀掉旧进程（换成实际 PID）
kill 12345
```

或改 `configs/config.yaml`：

```yaml
server:
  port: 12801
```

**Q4：启动后访问 8080 打不开**

端口是 **12800**：<http://127.0.0.1:12800>。README 里的 8080 是错的。

**Q5：启动日志在哪？**

用 `./start.sh` 前台运行直接看输出；后台运行可：

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
nohup ./lingops-server > /tmp/lingops.log 2>&1 &
tail -f /tmp/lingops.log
```

**Q6：页面白屏 / 还是旧版本**

`serve_frontend: true` 时由后端托管 `frontend/dist`。强制刷新（Cmd+Shift+R），确认 `frontend/dist/index.html` 存在，且 `configs/config.yaml` 里 `serve_frontend` 为 `true`。

---

## 二、登录

**Q7：`admin/admin123` 登不上**

- 密码已被改过 → 见 Q8；
- 数据库被替换/损坏 → 看 `data/lingops.db` 是否存在；
- 后端未启动 → `curl http://localhost:12800/health`。

**Q8：忘记密码**

没有找回入口。两种办法：

1. 用已知 bcrypt 哈希更新（先停服）：
   ```bash
   sqlite3 data/lingops.db "update users set password='<bcrypt-hash>' where username='admin';"
   ```
2. 删库重来（**丢数据**）：停服 → `mv data/lingops.db data/lingops.db.bak` → 启动。

**Q9：一直 401 / 刚登录就掉线**

- token 存在 localStorage，清除站点数据后需重登；
- 改过 `jwt.secret` 或改过密码，旧 token 失效；
- 系统时间偏差过大也会导致 JWT 校验失败。

**Q10：能改用户名吗？**

不能。设置页明确「用户名不可修改」，只能改密码。

---

## 三、网络与目标连通性

**Q11：WebShell 测试连接失败**

按顺序排查：

1. URL 是否从 **LingOps 所在机器** 能访问（`curl -I <url>`）；
2. 密码是否与马里的 `pass` 一致；
3. 马是否支持 POST（有些被改成 GET）；
4. 目标是否禁用 `eval`、是否有 WAF 拦截 POST；
5. `127.0.0.1` 在远程靶场里指的是 LingOps 自己，不是靶机。

**Q12：SSH 连不上**

- 端口不是 22 时要在资产里改；
- 密码登录被禁用 → 平台只支持密码认证（无密钥输入框），需在靶机开启 `PasswordAuthentication` 或改用 WebShell；
- 目标只允许指定网段 → 换跳板/加白；
- 检查 `ssh -p <port> <user>@<host>` 手工是否可连。

**Q13：侦察扫不到主机**

- 目标禁 ping：调大 `timeout`，或改用端口扫描确认；
- 地址段写错：支持 `192.168.1.1`、`192.168.1.10-50`、`192.168.1.2:1000-2000`、`baidu.com:70-90`；
- 本机防火墙/VPN 分流导致回包丢失。

**Q14：进度条不动 / 实时日志不刷新**

侦察页 WS 地址在前端硬编码为 `localhost:12800`。在**运行 LingOps 的机器上**打开浏览器即可；远程访问时任务仍在后台跑，刷新页面看结果。

---

## 四、功能相关

**Q15：权限维持提示上传失败**

v0.2 的投放是「基点 Shell 执行 + 浏览器触发启动器」：

- 基点 Shell 必须**在线**且目录可写；
- 不死马/内存马依赖 `ignore_user_abort`、`set_time_limit`，被禁用就失败；
- 启动器 URL 必须能从浏览器访问（否则不会生成目标文件）；
- 后端没有 `/persistence/upload`、`/persistence/:id/cleanup` 路由，这是前端遗留调用，属正常现象。

**Q16：WebShell 扫描支持哪些语言/格式？**

语言：php / python / java / nodejs / go；格式：单文件，或 ZIP / tar.gz。扩展名白名单：`.php .phtml .php3 .php4 .php5 .inc .py .pyw .java .jsp .jspx .js .ts .go`。

**Q16b：文件管理器打开后是 `$RECYCLE.BIN`、`Program Files`，文件夹还点不开？**

这是 Windows 目标的兼容性问题：官方前端把 `/` 当根目录，PHP 侧把 `path=/` 拼成 `//名字`，Windows 视为 UNC 路径，`is_dir()` 全失败 → 所有条目 `isDir=false`（图标是文件、双击只去读文件），而且 `/` 指向的是盘符根而不是你上传 shell 的目录。

已由扩展补丁修复：打开即定位到 shell 所在目录、**单击**即可进入文件夹、列表首行有 `..` 可回上级。详见 [03 章 7.1](03-shells.md#71-windows-目标的坑已修复)。
想改成默认停在盘符根：控制台执行 `localStorage.lp_fs_root='C:'` 后刷新。

**Q17：WAF 部署成功但不拦截**

- 必须是 PHP-FPM/FastCGI，Apache `mod_php` 下 `.user.ini` 不生效；
- 确认 `web_root` 下生成了 `.user.ini` 且 `auto_prepend_file` 指向 `waf.php`；
- 确认目录/文件属主与 PHP-FPM 运行用户一致；
- 看日志 `/tmp/waf_attack.txt`。

**Q18：基线任务一直「运行中」**

- SSH 会话掉线 → 重新测试连接；
- 命令卡住（如 `mysql_passwd` 等待输入）→ 取消任务；
- 长任务（全盘扫描/备份）需要时间，看「执行日志」。

**Q19：文件监控没有差异**

先执行 `action=create` 建基线，之后再 `action=check`；两次之间文件确实变化才会出现 added/modified/deleted。

**Q20：数据库管理只能加 MySQL？**

UI 的类型下拉只放了 MySQL。后端与终端快捷命令支持 PostgreSQL/Redis，但发布版界面未开放；需要时可调 API 直接建资产。

**Q21：数据库备份里没有库**

「选择要备份的数据库」会实时查询；列表为空说明连接失败或账号无权限。先点「测试连通性」。

**Q22：Flag 读取一直是失败**

- `flag_path` 不对（默认 `/flag`，有些题目在 `/flag.txt`、`/root/flag`）；
- WebShell 用户无读权限；
- 马被删/密码改了；
- 点任务详情看「读取记录」里的错误信息。

**Q23：AWDP 扫描没结果**

- 语言选错；
- 规则被禁用：看「当前语言可用规则」；
- ZIP 要走后台任务，等进度完成；
- 代码太大被截断，改用上传。

**Q24：patch.sh 执行后服务挂了**

看 `/opt/app.log`；核对目标路径、主文件名、启动用户权限；先手动 `cp` + 重启验证，再批量。

**Q25：团队页面什么都没有**

官方 `/team` 本来就是占位页（“团队信息、成员管理等功能正在开发中”）。**扩展版曾加过「团队作战室」，v1.3.2 已移除**——
它要单开 SQLite（`data/team.db`）、还要往 12801 加路由，单人打 AWD 用不上，反而多一层维护面。

要多人协作，直接用官方的 `/api/v1/users` 建多个账号（见 [13 团队与设置](13-team-settings.md)），
或者把 `docs/` 里的复盘模板导出来共享。

---

## 五、数据与备份

**Q26：数据存在哪？**

`data/lingops.db`（SQLite）。备份/迁移只认这一个文件。

```bash
# 停服后
cp data/lingops.db data/lingops.db.$(date +%F)
```

**Q27：`database is locked`**

SQLite 并发写冲突。停掉重复启动的多个 `lingops-server` 进程，避免同时跑大量写任务：

```bash
pgrep -fl lingops-server
```

**Q28：升级会丢数据吗？**

保留 `configs/` 和 `data/`，只替换二进制和 `frontend/`，数据不丢。跨大版本先备份 DB。

**Q29：怎么彻底重置？**

```bash
# 停服
mv data/lingops.db data/lingops.db.bak
./start.sh
```

会重新建库并灌入内置知识库（1047 条知识 / 759 条规则 / 49 个 WAF 模板）。

---

## 六、安全提醒

- 默认 `admin/admin123` 和 `jwt.secret: change-me` 必须改；
- 平台本身能读写目标服务器，**不要暴露到公网**；
- 所有操作只用于授权环境；
- 比赛结束清理自己投放的后门与计划任务。
