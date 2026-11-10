# LingOps v0.2 使用教程（总目录）

LingOps 是一个面向 **AWD / AWDP 攻防对抗** 的一体化平台：把目标侦察、Shell 管理、木马生成、权限维持、WebShell 查杀、WAF 部署、主机基线加固、数据库运维、Flag 批量读取、AWDP 漏洞扫描与补丁生成集中到一个 Web 控制台里。

- 版本：v0.2.0（darwin/arm64 发布包）
- 默认地址：<http://127.0.0.1:12800>
- 默认账号：`admin` / `admin123`（首次登录后请立即修改）

> ⚠️ **合法使用声明**：本工具仅可用于你拥有明确授权的资产、自建靶场或 CTF/AWD 比赛环境。未经授权对第三方系统进行扫描、植入、提权、数据读取均属违法行为，后果由使用者自行承担。

---

## 一、启动与登录

### 1. 正确启动方式（重要）

发布包解压后的目录结构：

```
LingOps_v0.2_darwin_arm64/
├── lingops-server          # 主程序
├── start.sh                # 启动脚本（推荐）
├── configs/config.yaml     # 配置文件
├── data/lingops.db         # SQLite 数据库（所有数据都在这里）
├── frontend/dist/          # 前端静态文件
├── ext/                    # 【扩展】端口/上传点扫描后端
├── start-ext.sh            # 【扩展】单独启动扫描后端
└── docs/                   # 教程（本目录）
```

**推荐：**

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
./start.sh
```

`start.sh` 会先 `cd` 到脚本所在目录，再启动 `./lingops-server`，因此能正确找到 `./configs/config.yaml`。

**为什么直接在家目录运行会失败？**

在 `~` 下执行绝对路径时，程序会按 `$HOME/configs`、`$HOME`、`/etc/lingops` 的顺序找名为 `config` 的配置文件，而你的配置在发布包的 `configs/` 目录里，所以报：

```
Failed to load config: failed to read config:
Config File "config" Not Found in "[/Users/shu/configs /Users/shu /etc/lingops]"
```

三种解决办法（任选其一）：

1. 用 `start.sh` 启动（最简单）；
2. 先 `cd` 到发布包目录再执行 `./lingops-server`；
3. 让它在任何目录都能启动：`mkdir -p ~/configs && cp configs/config.yaml ~/configs/config.yaml`。

> 注意：配置文件里的端口是 **12800**，不是 README 里写的 8080。若被占用，修改 `configs/config.yaml` 中的 `server.port` 后重启。

**Windows 用户（win64 包）：不用装 Python。** `LingOps_v0.2_win64_enhanced.zip` 里自带
便携版 Python 3.11（`python/` 目录），解压后双击 `start.bat` 即可，扩展后端
（端口扫描 / 上传点 / AI 修复包，端口 12801）会自动用包内 `python\python.exe` 启动：

- 想用自己装的 Python：删掉 `python\` 目录，`start.bat` 会退回 `python` → `py -3`；
- 扩展后端只用标准库，**不需要 `pip install`**；
- `stop.bat` 按端口 12800 / 12801 杀进程，不用记 PID。

### 2. 首次登录

1. 浏览器打开 <http://127.0.0.1:12800>；
2. 输入 `admin` / `admin123`；
3. 登录后到「设置」页修改密码（修改后需要用新密码重新登录）。

### 3. 数据与备份

所有业务数据（Shell、任务、知识库、数据库资产等）都在 `data/lingops.db` 这一个 SQLite 文件里。

- 备份：停服后复制 `data/lingops.db` 即可；
- 重置：停服后删除/改名该文件，重启会重新建库并写入内置知识库；
- 升级：替换二进制与 `frontend/`，保留 `configs/` 和 `data/`。

---

## 二、功能地图

| 菜单 | 路径 | 作用 | 教程 |
|---|---|---|---|
| 总览 | `/dashboard` | 全局统计、快捷入口、AWD 流程提示 | [01 总览](01-dashboard.md) |
| 侦察 | `/discovery` | 批量主机存活探测、历史任务（端口/服务扫描走 API） | [02 侦察](02-discovery.md) |
| 端口扫描（扩展） | 侧边栏「端口扫描」 | 存活探测（ICMP+TCP）+ 端口扫描 + 服务指纹 + Web 探测 + **上传点探测** | [17 端口与上传点](17-port-upload-scan.md) |
| 攻击 → Shell 管理 | `/attack/shells` | WebShell / SSH 资产管理、终端、文件管理 | [03 Shell 管理](03-shells.md) |
| 攻击 → 木马生成 | `/attack/trojan` | PHP/JSP/ASPX 一句话与变体生成 | [04 木马生成](04-trojan.md) |
| 攻击 → 权限维持 | `/attack/persistence` | 基于已有 WebShell 投放不死马/内存马 | [05 权限维持](05-persistence.md) |
| 防御 → WebShell 扫描 | `/defense/webshell` | 源码级后门查杀（多语言、支持压缩包） | [06 WebShell 扫描](06-webshell-scan.md) |
| 防御 → WAF 管理 | `/defense/waf` | 通过 SSH 一键部署 PHP 软 WAF | [07 WAF 管理](07-waf.md) |
| 运维 → 基线管理 | `/ops/baseline` | 备份、巡检、权限、后门清理、端口封禁等 | [08 基线管理](08-baseline.md) |
| 运维 → 数据库管理 | `/ops/database` | MySQL 资产（UI 仅开放 MySQL）、终端、备份恢复 | [09 数据库管理](09-database.md) |
| Flag | `/flag` | 定时批量读取 Flag、成绩统计 | [10 Flag 读取](10-flag.md) |
| Flag 查找（扩展） | 侧边栏「Flag 查找」/ `/flag` 页按钮 | **自动搜索** flag 文件、正则提取、一键加入监控 | [18 Flag 查找](18-flag-hunt.md) |
| 木马免杀生成器（扩展） | `/attack/trojan` 页「🛡 免杀生成器」 | **三档免杀** + 图片马/图标伪装 + `.htaccess`/`.user.ini` | [19 木马免杀](19-trojan-evasion.md) |
| 木马生成器 v2（扩展） | 同上，面板内「加密 / 伪装」下拉 | **加密信道**（XOR/AES/Base64）+ 五种真实图片马 + `connect.py`/`selftest.php` | [22 哥斯拉级木马](22-trojan-godzilla.md) |
| ARTEX（集成） | 侧边栏「ARTEX」 | **LLM 多智能体自治渗透**，全屏内嵌，`start.sh` 一键同起 | [23 ARTEX](23-artex.md) |
| AWDP → Break | `/awdp/break` | 源码漏洞发现、Payload/Exploit/绕过知识库 | [11 AWDP Break](11-awdp-break.md) |
| AWDP 深度审计（扩展） | `/awdp/break`、`/awdp/fix` 页「🔬 深度审计」 | **跨行污点分析**，补官方引擎漏报 + 一键对比官方结果 + **88 个回归样本可自测** | [20 AWDP 深度审计](20-awdp-deep-scan.md) |
| AI 修复包（扩展） | 上传 ZIP 后自动弹出 / 深度审计面板顶部 | **源码+问题清单落盘 + 本地链接**，直接交给本地或在线 AI 修漏洞 | [21 AI 修复包](21-ai-fix-bundle.md) |
| AWDP → Fix | `/awdp/fix` | 漏洞扫描、知识库、规则、补丁包生成 | [12 AWDP Fix](12-awdp-fix.md) |
| 团队 | `/team` | 占位页（“功能正在开发中”）；侧边栏「团队作战室」扩展已在 v1.3.2 移除 | [13 团队与设置](13-team-settings.md) |
| 设置 | `/settings` | 账号信息与改密 | [13 团队与设置](13-team-settings.md) |

附：

- [14 API 参考](14-api-reference.md)：接口清单、鉴权、curl 示例（适合脚本化/二次开发）
- [15 常见问题](15-faq.md)：启动、登录、网络、任务、数据相关排查
- [16 比赛速查表](16-cheatsheet.md)：一页纸流程与常用命令
- [17 端口扫描与上传点探测](17-port-upload-scan.md)：**扩展模块**，官方 UI 没有的端口/上传点扫描能力；含「ICMP+TCP 深度探活」（解决官方探测扫不到丢 ICMP 的靶机）
- [18 Flag 查找](18-flag-hunt.md)：**扩展模块**，自动搜索 flag 文件并提取值（官方只能手填固定路径）
- [19 木马免杀生成器](19-trojan-evasion.md)：**扩展模块**，三档混淆 + 图片马/自定义图标 + 配套 `.htaccess`/`.user.ini`（官方模板是明文一句话）
- [20 AWDP 深度审计](20-awdp-deep-scan.md)：**扩展模块**，跨行污点分析 + 官方漏报对比（官方引擎是「污点门控 + 正则」，Go RCE / Java 反序列化 / LDAP / 二级变量全漏）；误报用 `lingops:ignore` 标记抑制；自带 88 个已知答案样本，`node tests/awdp-corpus/run.js` 一键自测；屏蔽层另有 `oracle/mask-audit.js` 可拿真实代码压测
- [21 AI 修复包](21-ai-fix-bundle.md)：**扩展模块**，上传 ZIP 自动生成 `~/LingOps-AWDP/<id>/`（源码 + `bundle.md` + `prompt.txt`）与 `http://127.0.0.1:12801/awdp/<id>/` 链接，交给本地/在线 AI 修漏洞
- [22 木马生成器 v2](22-trojan-godzilla.md)：**扩展模块**，XOR+Base64（哥斯拉兼容）/ AES-128-CBC / Base64 加密信道 + md5 标记定位图片马 + 一键 `connect.py` 与 `selftest.php`
- [23 ARTEX 自治渗透](23-artex.md)：**集成模块**，侧边栏「ARTEX」内嵌 8787 完整界面，`start.sh` 自动拉 PostgreSQL(5433) + ARTEX(8787)；账号 `admin` / 密码 `admin123`（界面只输密码），需配 LLM 才会真正跑任务
- [24 命令行版审计](24-cli-audit.md)：**CLI**，`cli/awdp-audit <目录|文件|zip>`，与网页端深度审计**同一套引擎、规则零漂移**；支持 `-f json`、`--fail-on` 退出码卡 CI、`--exclude`、`--min-sev`；只要 Node ≥ 18，零依赖，全仓库 130 文件约 220ms
- [变更记录 CHANGELOG](../CHANGELOG.md)：**这包到底改了什么**，按版本列（v1.1 扩展模块 / v1.2 修漏报 / v1.3 修净化诱饵），以及怎么确认拿到的是改过的包（v1.3.1 修了 5 个「屏蔽过度导致漏报」的 bug）

---

## 三、典型 AWD 流程

```
① 侦察（/discovery）
   探活拿到靶机 IP 列表
        ↓
② 找入口 / 拿 Shell（/attack/shells + /attack/trojan）
   上传或利用漏洞写入一句话，登记为 WebShell 资产并测试连接
        ↓
③ 提权与维持（/attack/persistence）
   投放不死马/内存马，避免被对手删马后失联
        ↓
④ 加固与防守（/ops/baseline + /defense/waf + /defense/webshell）
   备份网站、清理对手后门、标准化权限、封禁异常端口、部署 WAF
        ↓
⑤ 得分（/flag）
   选择可用 WebShell，定时读取 /flag，观察成功/失败统计
        ↓
⑥ AWDP 轮次（/awdp/break → /awdp/fix）
   Break 阶段找漏洞打对手；Fix 阶段扫自己代码、打补丁、生成 patch 包
```

每一轮 AWDP 的节奏通常是：**先 Fix 保分（避免被打穿），再 Break 抢分**。补丁包要在平台给定的时间内提交/部署，否则本轮不得分。

---

## 四、几个容易踩的坑

1. **端口是 12800**，不是 8080。
2. **必须从发布包目录启动**，否则找不到配置。
3. **WebShell 的 URL 必须是 LingOps 所在机器能访问到的地址**；在容器/远程靶场里 `127.0.0.1` 指的是 LingOps 自己。
4. **WebShell 只支持 PHP**（一句话密码连接）；**SSH 只支持密码认证**，界面没有私钥输入框。
5. **WAF 部署依赖 PHP-FPM/FastCGI + `.user.ini`**，Apache `mod_php` 下不生效。
6. **基线管理、WAF、SSH 终端都需要「在线」的 SSH 资产**；先测试连接再操作。
7. 前端部分 WebSocket 地址被硬编码为 `localhost:12800`，**请在运行 LingOps 的机器上用浏览器访问**，从其他机器打开时实时进度可能不刷新（任务本身仍在后台执行）。
8. 所有「一键」操作（清理后门、封端口、改密码、恢复数据库）都有破坏性，**先看参数说明，能 dry-run 就先 dry-run**。
9. 「端口扫描」是**扩展模块**（非官方功能），需要额外启动 `12801` 服务；官方升级覆盖前端后需重新注入，见 [17 章](17-port-upload-scan.md#七维护)。
10. 「Flag 查找」也是**扩展模块**，纯前端注入、不依赖额外服务；官方 `/flag` 只能填一个固定路径，找不到 flag 时用它搜索，见 [18 章](18-flag-hunt.md)。
11. 官方「木马生成」只有 12 个明文固定模板，过不了任何查杀；用 `/attack/trojan` 页的「🛡 免杀生成器」做三档混淆和图片马，见 [19 章](19-trojan-evasion.md)。
12. **AWDP 扫描别只信官方结果**：官方引擎是「污点门控 + 正则」，只扫「含 source 或引用被污染变量」的行，且不传播二级变量、Go 只覆盖文件操作。`go/cmd.go`、`java/Deser.java`、`php/ldap.php` 这类是实测漏报。用「🔬 深度审计」补，并点「对比官方引擎」看漏了哪些文件，见 [20 章](20-awdp-deep-scan.md)。
13. **AI 修复包要扩展后端**：上传 ZIP 后自动生成的 `http://127.0.0.1:12801/awdp/<id>/` 链接只在本机有效，
    在线 AI 打不开，得用「复制 AI 提示词 + 复制全文源码」或上传 `bundle.md`；源码会落在 `~/LingOps-AWDP/`，赛后记得删。见 [21 章](21-ai-fix-bundle.md)。
14. **Windows 目标的 WebShell 文件管理器**：官方把 `/` 当根目录，会显示盘符根且文件夹点不开（`isDir` 全为 false）。已由注入补丁修复（首页改为 shell 所在目录、单击进目录、注入 `..` 行），详见 [03 章 7.1](03-shells.md#71-windows-目标的坑已修复)。
15. **ARTEX 需要 PostgreSQL**：`start.sh` 只负责「启动」不负责「安装」。没装 `postgresql@16` 时 ARTEX 会报 `open stores: database configuration not found`。界面只有一个密码框（密码 `admin123`）；写脚本调 API 时用户名写 **`admin`**（本包已把 `ARTEX` 全链路改掉）。见 [23 章](23-artex.md)。
16. **深度审计报的误报怎么办**：别改代码去迎合扫描器，在命中行（或上一行）加 `// lingops:ignore 理由` 即可，被忽略的条数会显示在汇总里。工具本身就要出网/读任意路径的（爬虫、指纹识别）属于这种情况。见 [20 章第十节](20-awdp-deep-scan.md#十误报怎么处理lingopsignore)。
17. **不确定扫描器靠不靠谱？自己跑**：`node tests/awdp-corpus/run.js` 会用 88 个已知答案的样本（真漏洞 34 / 安全写法 27 / 回归 12 / 对抗 15）验证引擎，退出码 0=全绿。改过引擎规则必须先跑它 —— 见 [20 章第十一节](20-awdp-deep-scan.md#十一自己验证引擎回归自测)。
18. **怀疑「扫不出漏洞」是引擎自己的错时**：深度审计是「先抹注释/字符串，再找 sink」，第一段抹多了就必然漏报，而 `node --check` 查不出这种错。用 `node tests/awdp-corpus/oracle/mask-audit.js <目录>` 拿真实代码压测屏蔽层——它会把每个文件屏蔽后**再编译一遍**，编译不过就是抹多了。v1.3.1 靠它抓出 5 个这类 bug（Python `//` 整除被当注释、JS 正则字面量里的引号、JS 嵌套模板字符串、PHP shebang、PHP heredoc 里的 `/*`），见 [20 章十一](20-awdp-deep-scan.md#屏蔽层单独测oraclemask-auditjs)。

19. **不想开浏览器、或者要批量扫/卡 CI**：用命令行版 `cli/awdp-audit`，和网页端深度审计**同一份引擎代码**（运行时从 `awdpplus.js` 切出分析段），规则零漂移、零 npm 依赖、只要 Node ≥ 18。`awdp-audit ./src -s high --fail-on high` 有问题就退出码 1，直接挂到 pre-commit / GitHub Actions 上。见 [24 章](24-cli-audit.md)。
