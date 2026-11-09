# 16 AWD 速查表

> 一页纸：开赛 10 分钟清单 + 常用命令 + 各功能入口。详细说明点对应教程。

## 0. 开赛前 5 分钟

```bash
# 启动
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64" && ./start.sh
# 打开
open http://127.0.0.1:12800        # admin / admin123
# 改密 + 改 jwt secret
vi configs/config.yaml             # jwt.secret: change-me
# 备份数据
cp data/lingops.db data/lingops.db.bak
```

## 1. 标准流程（按顺序）

| 步骤 | 页面 | 动作 | 教程 |
|---|---|---|---|
| 1 | 侦察 | 填 IP 段 → 开始 → 记录在线主机 | [02](02-discovery.md) |
| 1.5 | 端口扫描 | 目标/端口 → 开始 → 看开放端口 + 上传点（扩展） | [17](17-port-upload-scan.md) |
| 2 | Shell 管理 | 添加 WebShell/SSH → 测试连接 | [03](03-shells.md) |
| 3 | 基线管理 | `backup` 备份网站 | [08](08-baseline.md) |
| 4 | 基线管理 | `clean_backdoor`（先 dry-run）清对手马 | [08](08-baseline.md) |
| 5 | 基线管理 | `permission` + `php_secure` + `port_block` | [08](08-baseline.md) |
| 6 | 权限维持 | 投不死马/内存马 | [05](05-persistence.md) |
| 7 | WAF 管理 | 部署 `waf1` 通防 | [07](07-waf.md) |
| 8 | Flag | `flag_path=/flag`，`interval=30`，起任务 | [10](10-flag.md) |
| 9 | 基线管理 | `file_monitor` 建基线，定期 check | [08](08-baseline.md) |
| 10 | AWDP | Break 找洞 → Fix 打补丁 | [11](11-awdp-break.md) / [12](12-awdp-fix.md) |

## 2. 基线动作速查

| type | 关键参数 | 用途 |
|---|---|---|
| `backup` | `target_path=/var/www/html`、`backup_path=/tmp/backups` | 赛前备份 |
| `audit` | `web_root` | 安全巡检（可下报告） |
| `clean_backdoor` | `target_path`、`dry_run=true` | 查杀后门 |
| `permission` | `target_path`、`owner=www-data:www-data` | 权限标准化 |
| `readonly` | `target_path`、`restore=false` | 目录只读 |
| `mysql_passwd` | `old_password`、`new_password` | 改 MySQL 密码 |
| `ssh_passwd` | `new_password`、`confirm_password` | 改 SSH 密码 |
| `php_secure` | `disable_functions`、`open_basedir` | PHP 加固 |
| `port_block` | `port=3306`、`action=block`、`protocol=tcp` | 封端口 |
| `kill_reverse` | `dry_run=true` | 杀反弹 Shell |
| `file_monitor` | `target_path`、`action=create/check` | 文件监控 |

> 破坏性动作先 `dry_run`，改密前确认新密码已记录。

## 3. 常用命令（Shell 终端里）

```bash
# 找对手的马（按时间/权限/内容）
find /var/www/html -name "*.php" -mmin -60 -ls
find /var/www/html -name "*.php" -perm -o+w -ls
grep -rEl "eval\(|assert\(|base64_decode\(|system\(|passthru\(" /var/www/html --include=*.php

# 不死马进程
ps aux | grep -E "php|httpd" | grep -v grep
ls -la /proc/<pid>/cwd          # 看进程工作目录

# 查连接 / 反弹
ss -antp | grep ESTAB
crontab -l; ls -la /etc/cron.*; cat /etc/rc.local

# 查 SSH 后门
cat ~/.ssh/authorized_keys
grep -v "^#" /etc/ssh/sshd_config | grep -Ei "port|permitroot|password"

# 文件时间线
find /var/www/html -type f -printf "%TY-%Tm-%Td %TH:%TM %p\n" | sort -r | head -30
```

## 4. 端口/服务

```bash
ss -lntp
lsof -nP -iTCP -sTCP:LISTEN
# 本机快速探活
for p in 22 80 3306 6379 8080; do (echo >/dev/tcp/127.0.0.1/$p) 2>/dev/null && echo "$p open"; done
```

## 5. Flag

```bash
cat /flag; cat /flag.txt; find / -maxdepth 3 -name "flag*" 2>/dev/null
```

平台里：Flag 页 → 选 WebShell → `flag_path` → `interval` → 启动；一个 WebShell 对应一个队伍。

## 6. AWDP 轮次

```
Fix（保分）：
  备份 → 上传源码 ZIP → 扫描 → 看高危 → 查看知识 → 改代码
  → Patch 工作台 → 下载 patch.tar.gz → 靶机执行 → 复扫

Break（抢分）：
  上传对手源码 → 扫描 → Payload/Exploit 库 → 构造请求 → 拿 Flag
```

```bash
# 靶机打补丁
tar -xzf patch.tar.gz -C /tmp/patch && cd /tmp/patch && chmod +x patch.sh && ./patch.sh
```

## 6.5 端口/上传点扫描速查（扩展）

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
./start.sh                       # 同时起 12800 平台 + 12801 扫描后端
bash start-ext.sh                # 或单独起扫描后端
```

| 场景 | 操作 |
|---|---|
| 界面扫描 | 登录 → 左侧「端口扫描」→ 填目标 → 选端口 → 开始 |
| 快速摸对手 Web | 端口选「Web 常用」+ 上传点探测，强度「标准」 |
| 找上传点并验证 | 勾「主动上传测试」（会在目标留 `lp_probe.txt`） |
| 全端口 | 端口选「全端口」+ 并发 500-800，很慢很吵 |
| 结果入库 | 结果区「写入资产库」（按 IP 去重） |
| 导出 | 右上「导出 JSON / CSV」 |
| 命令行 | `python3 ext/lp_scan_server.py --scan 10.0.0.0/24 -p common --upload` |
| 卸载扩展 | `bash ext/uninstall.sh` |

> 主动上传测试默认关闭；对自己机器/生产环境别开。

## 7. 端口与路径速记

| 项 | 值 |
|---|---|
| Web 端口 | `12800` |
| 扫描扩展端口 | `12801` |
| 数据库 | `data/lingops.db` |
| 配置 | `configs/config.yaml` |
| 启动 | `./start.sh` |
| 默认账号 | `admin / admin123` |
| WAF 日志 | `/tmp/waf_attack.txt` |
| 默认 Flag 路径 | `/flag` |
| 默认 Web 根 | `/var/www/html` |
| 默认备份目录 | `/tmp/backups` |

## 8. 出事怎么办

| 现象 | 先做 |
|---|---|
| 马被删 | 权限维持重投 → 基线 `file_monitor` 查改动 |
| 服务挂 | `patch.sh` 回滚/备份还原 → 看 `/opt/app.log` |
| 被提权 | 基线 `audit` + `kill_reverse` + 改所有密码 |
| Flag 掉了 | Flag 页看读取记录 → 手动 `cat /flag` 验证 |
| 平台打不开 | `pgrep -fl lingops-server` → 看 `/tmp/lingops.log` |
| 数据异常 | 停服 → 用 `lingops.db.bak` 恢复 |
