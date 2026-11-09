# LingOps AWD/AWDP Enhanced · 灵控攻防增强版

> **一个给 AWD / AWDP 攻防竞赛用的单机作战控制台。**
> 基于 [灵控 LingOps v0.2.0](https://github.com/zhanglinglingc/lingops) 二次增强，官方二进制零修改。

![platform](https://img.shields.io/badge/platform-macOS%20arm64%20%7C%20Windows%20x64-blue)
![version](https://img.shields.io/badge/version-1.3.3-green)
![docs](https://img.shields.io/badge/docs-23%20%E7%AB%A0-orange)

> 📄 网页版介绍页：源码在 [`site/index.html`](site/index.html)（单文件、零外部依赖）。
> 组织 owner 在 **Settings → Pages** 把 Source 设为 `Deploy from a branch` → `main` → `/site` 后，
> 即可通过 `https://gewu-academy.github.io/LingOps-Enhanced/` 访问。

---

## 目录

- [一、这个项目是干什么的](#一这个项目是干什么的)
- [二、AWD 比赛到底在打什么](#二awd-比赛到底在打什么)
- [三、它解决哪些具体问题](#三它解决哪些具体问题)
- [四、功能全览](#四功能全览)
- [五、快速开始](#五快速开始)
- [六、架构：扩展是怎么挂上去的](#六架构扩展是怎么挂上去的)
- [七、目录结构](#七目录结构)
- [八、部署前必改](#八部署前必改)
- [九、自测与回归](#九自测与回归)
- [十、已知限制](#十已知限制)
- [十一、免责与致谢](#十一免责与致谢)

---

## 一、这个项目是干什么的

**一句话**：把你打 AWD 比赛时散落在十几个终端、浏览器标签页、记事本里的操作，收进一个本地网页控制台。

AWD（Attack With Defense）是 CTF 里的一种赛制：每支队伍分到一批服务器，上面跑着有漏洞的 Web 应用，同时还藏着 flag 文件。比赛期间你要同时做三件事：

1. **攻** —— 找到别人机器上的漏洞，打进去，把 flag 交上去得分；
2. **守** —— 别人也在打你，你要在漏洞被利用之前把它修掉；
3. **抢** —— flag 定时刷新，谁先读到谁先交分。

这三件事要在几十分钟里并行做，而且对手每轮都在换 payload。**真正的瓶颈不是「会不会打」，而是「手忙不过来」**：你要管理 10~50 台靶机的 WebShell、盯着哪台被打穿了、记住哪个 payload 有效、把修好的代码同步上去。

灵控（LingOps）就是干这个的 —— 一个跑在本机的 Go 程序，提供一个网页控制台，把所有靶机、Shell、任务、知识库集中管起来。

**这个仓库做的事**：官方版功能不够用（尤其 AWDP 代码审计漏报严重、没有端口/上传点扫描、Flag 要手填路径），所以我在**不改官方二进制**的前提下，用运行时注入的方式补了一批能力，并集成了一个 LLM 自治渗透工具 ARTEX。

---

## 二、AWD 比赛到底在打什么

理解这个才能理解为什么需要这些功能。

### 2.1 典型一轮的循环

```
       ┌──────────────────────────────────────────────┐
       │                                              │
       ▼                                              │
 ① 侦察：哪些靶机活着？开了什么端口？哪个有上传点？      │
       │                                              │
       ▼                                              │
 ② 打点：上传/写入 WebShell，拿到命令执行              │
       │                                              │
       ▼                                              │
 ③ 提权/横向：从 Web 目录走到系统层，找 flag 文件        │
       │                                              │
       ▼                                              │
 ④ 交 flag：读取 → 提交 → 记分                        │
       │                                              │
       ▼                                              │
 ⑤ 防守：自己的机器被打了，找后门 → 清掉 → 补漏洞        │
       │                                              │
       └──────────────────────────────────────────────┘
```

一轮通常 5~15 分钟，全程要重复 10~30 轮。

### 2.2 选手真正会遇到的困难

| 环节 | 现实情况 |
|---|---|
| **侦察** | 靶机列表是 IP 段，几十台。哪台活着、开了 8080 还是 80、有没有 `/upload.php`，只能自己扫。官方工具只做 ICMP 存活探测，靶机丢 ICMP 就全部显示「离线」 |
| **打点** | 拿到 Shell 后要立刻能执行命令、传文件、翻目录。手动 `curl` 构造请求太慢 |
| **找 flag** | flag 可能在 `/flag`、`/root/flag`、`/var/www/flag.php`、站点根目录、`/tmp`…… 名字可能是 `flag`、`flag.txt`、`x_flag`、`flag.jpg`。**官方只能手填一个固定路径**，猜错就一直失败 |
| **防守** | 对手可能已经放了不死马、内存马。你得扫源码找后门、比对文件哈希、封 IP |
| **AWDP 修漏洞** | AWDP 是 AWD 的变种：给你**源码**，要求你找出漏洞并修掉。官方扫描引擎漏报严重（下面细说），修不完就持续丢分 |

---

## 三、它解决哪些具体问题

### 3.1 「靶机明明活着，工具说离线」

**原因**：官方侦察只发 ICMP（ping）。很多比赛环境为了防扫描会把 ICMP 全 drop，靶机就全变「离线」。

**解决**：扩展的端口扫描模块用 **ICMP + TCP 双栈探活** —— ping 不通就试 22 / 80 / 443 / 445 / 3389 等常见端口，只要有一个 TCP 握手成功就判定存活。实测能救回官方漏掉的大部分靶机。

### 3.2 「不知道哪个端口有上传点」

**原因**：官方没有端口扫描，更没有上传点探测。

**解决**：扩展模块做了完整链路：

```
存活探测 → 端口扫描（1-65535 或常用集） → 服务指纹（banner/HTTP 头）
        → Web 探测（标题/框架/路径） → 上传点探测（找 form/file input/常见上传接口）
```

上传点探测会主动请求常见路径（`/upload.php`、`/api/upload`、`/admin/upload` 等 40+ 条），检查响应里有没有文件上传表单或 JSON 上传接口，命中的直接列出来并给出 `curl` 测试命令。

### 3.3 「Flag 到底在哪」

**原因**：官方 `/flag` 页只有一个表单，路径必须手填，默认 `/flag`。

**解决**：Flag 查找扩展会在**你已经拿到的 WebShell** 上批量遍历候选路径：

- 常见绝对路径：`/flag`、`/flag.txt`、`/root/flag`、`/root/flag.txt`、`/home/*/flag`、`/tmp/flag`、`/var/www/flag` ……
- 站点目录递归：搜文件名含 `flag` 的文件（支持 `flag.php`、`x_flag.txt`、`flag.jpg`）
- Windows 路径：`C:\flag.txt`、`D:\flag`、`C:\inetpub\wwwroot\flag.txt`

搜到后用正则提取 flag 值（`flag{...}`、`DASCTF{...}`、32 位 hex 等），**一键转成官方监控任务**，之后官方那套定时读取就接管了。

### 3.4 「官方 AWDP 审计扫不出漏洞」

这是**最严重**的一个。官方 AWDP Break/Fix 的扫描引擎是「污点门控 + 正则」两级结构：

```
第一级：找 source（$_GET / getParameter / r.URL.Query() / request.args）
        ↓ 只有「含 source 的行」和「引用了被污染变量的行」才进第二级
第二级：在这些行上跑正则（system( / exec( / unserialize( ...）
```

设计上能压噪声，但有三个结构性漏报（都在 74 个漏洞样本上实测确认）：

**漏报 1：sink 参数里没有污点变量 → 整行不扫**

```php
system("ls -la");          // ❌ 官方不报（即使这是明摆着的命令执行）
myCustomFunc2("literal");  // ❌ 同上
```

**漏报 2：不传播二级变量**

```php
$f = $_GET['f'];      // 一级：被污染
$g = $f;              // 二级：官方引擎不传播
exec("cmd " . $g);    // ❌ 漏报
```

**漏报 3：Go 语义引擎只覆盖文件操作**

**解决**：我写了独立的深度审计引擎 `awdpplus.js`（2078 行 / 331 条规则），做**跨行污点分析**：

- 先抹掉注释和字符串（避免把文档里的 `system()` 当漏洞），但保留变量插值；
- 从 source 出发，沿赋值链传播到任意深度（`$a = $_GET[x]; $b = $a; $c = $b; system($c);`）；
- 追踪函数参数、数组元素、对象属性、`sprintf` / 字符串拼接；
- 支持 PHP / Python / Node.js / Java / Go / Ruby / ASP / C# 八种语言；
- 规则库 331 条：污点来源 66 + 危险函数 212 + 静态特征 53，覆盖 25 个漏洞类别；
- 结果可以和官方扫描**一键对比**（只看官方漏的 / 只看我多报的）。

配套 **88 个回归样本**（34 真漏洞 + 27 安全写法 + 15 对抗样本 + 12 回归），改引擎前后各跑一遍，防止「修一个漏报换来三个误报」。

### 3.5 「修漏洞改到手抽筋」

**原因**：官方扫描只给你一张问题列表，**不保留源码**（`data/` 里只有 `lingops.db` 和 `poc/`）。想交给 AI 修，得手动复制几十个文件。

**解决**：AI 修复包。上传一次 ZIP，立刻得到：

```
~/LingOps-AWDP/<id>/
├── src/                  # 解压的源码，保留原目录结构
├── index.html            # 目录页：问题清单 + 文件树 + 可点链接
├── bundle.md             # 全文包：元信息 + 问题清单 + 全部源码
├── attack-plan.md        # ⚔️ 攻击路线：每条漏洞的入口 / payload / 预期回显 / flag 位置
├── fix-plan.md           # 🛡️ 修复清单：每条根因 / 最小改动 / 验证方法 + 止血顺序
├── local-ai.md           # 🤖 给本地 AI 的任务书（整篇复制即可）
├── check_fixed.py        # ✅ 验收门：查语法/路径/换行/改动规模/已知坏写法/覆盖率
└── make_patch.py         # 📦 把 fixed/ 转成 git apply 能用的补丁
```

把这个目录丢给 Cursor / Claude / Copilot，它按 `local-ai.md` 的要求把改好的完整文件写进 `fixed/`，然后：

```bash
python3 check_fixed.py -v            # 全绿才能往下走
python3 make_patch.py fixed/         # 生成 fixes.patch
python3 make_patch.py fixed/ --apply-to <靶场根目录>   # 直接打上去
```

`check_fixed.py` 会拦下这些必错项：`fixed/` 为空 / 路径不存在 / 语法错误 / 换行风格被改 / 单文件改动超 50% / 命中已知坏写法 / 高危问题有文件没覆盖。

> 这套东西是真的能用的 —— 我用它审计 ARTEX 自己的压缩包，扫出 17 条问题，逐条修完跑通验收。

### 3.6 「木马一秒被查杀」

**原因**：官方木马页只有 12 个固定模板，明文 `eval($_POST['pass'])`，D盾、河马、安全狗一眼命中。

**解决**：两代免杀生成器。

**v1（静态免杀）**：三档混淆 + 图片马（真实图片头拼接，`getimagesize()` 判定为合法图片）+ 一键生成 `.htaccess` / `.user.ini` 让 `.jpg` 也能被 PHP 解析。

**v2（流量免杀）**：

| 能力 | v1 | v2 |
|---|---|---|
| 载荷加密 | 无 | **XOR+Base64 / AES-128-CBC / 纯 Base64 / 明文** 四种 |
| 通信协议 | `pass=base64(php)` | 加密信道 + **md5 标记包裹**响应 |
| 图片马 | 拼接图片头 | 同左，图标由 canvas 实时绘制（盾牌），非占位点 |
| 图标格式 | PNG/ICO | **GIF / PNG / JPG / BMP / ICO(256)** 五种，全部真实可解码 |
| 功能模式 | eval / cmd / 文件读写 | 增加 **file（完整文件管理器）/ db（mysqli）/ info（信息收集）** |
| 连接工具 | 手动构造 | **一键生成 `connect.py`**（含标记定位、自动禁代理） |
| 自检 | 无 | **一键生成 `selftest.php`** |
| 哥斯拉兼容 | 无 | XOR 模式与哥斯拉 `PHP_XOR_BASE64` **同构**，可直接用哥斯拉连 |

### 3.7 「想跑 LLM 自治渗透，但工具链要自己搭」

**解决**：集成了 ARTEX —— 一个 LLM 多智能体自治渗透框架，全屏内嵌在侧边栏「ARTEX」菜单里。`start.sh` 会一并拉起 PostgreSQL(5433) + ARTEX(8787)，账号 `admin` / 密码 `admin123`（界面只输密码）。

ARTEX 自带 skills（`api-recon` 做 API 侦察、`playwright-cli` 做浏览器自动化），配置好 LLM 后可以自己跑任务。本仓库已把它的界面和提示词汉化。

---

## 四、功能全览

### 官方自带

| 菜单 | 路径 | 作用 |
|---|---|---|
| 总览 | `/dashboard` | 全局统计、快捷入口、AWD 流程提示 |
| 侦察 | `/discovery` | 批量主机存活探测、历史任务 |
| 攻击 → Shell 管理 | `/attack/shells` | WebShell / SSH 资产管理、终端、文件管理 |
| 攻击 → 木马生成 | `/attack/trojan` | PHP/JSP/ASPX 一句话与变体生成 |
| 攻击 → 权限维持 | `/attack/persistence` | 投放不死马 / 内存马 |
| 防御 → WebShell 扫描 | `/defense/webshell` | 源码级后门查杀（多语言、支持压缩包） |
| 防御 → WAF 管理 | `/defense/waf` | 通过 SSH 一键部署 PHP 软 WAF |
| 运维 → 基线管理 | `/ops/baseline` | 备份、巡检、权限、后门清理、端口封禁 |
| 运维 → 数据库管理 | `/ops/database` | MySQL 资产、终端、备份恢复 |
| Flag | `/flag` | 定时批量读取 Flag、成绩统计 |
| AWDP → Break | `/awdp/break` | 源码漏洞发现、Payload（110 条）/ Exploit（53 条）/ WAF 绕过（73 条） |
| AWDP → Fix | `/awdp/fix` | 漏洞扫描、知识库（147 条）、规则（634 条）、补丁包生成 |
| 设置 | `/settings` | 账号信息与改密 |

### 本仓库新增

| 模块 | 入口 | 一句话 | 代码量 |
|---|---|---|---|
| **端口与上传点扫描** | 侧边栏「端口扫描」 | ICMP+TCP 双栈探活、端口扫描、服务指纹、Web 探测、上传点探测 | `ext/lp_scan_server.py` 2844 行 |
| **Flag 自动查找** | `/flag` 页按钮 | 遍历候选路径 + 正则提取 + 一键转监控任务 | `flaghunt.js` 673 行 |
| **木马免杀 v1** | `/attack/trojan` 页 | 三档混淆 + 图片马 + `.htaccess` / `.user.ini` | `trojanplus.js` 1140 行 |
| **木马生成器 v2** | 同上 | 加密信道 + 五种图片马 + 连接脚本 + 自检脚本 | 同上 |
| **AWDP 深度审计** | `/awdp/*` 页「🔬 深度审计」 | 跨行污点分析 + 331 条规则，补官方漏报，可与官方对比 | `awdpplus.js` 2078 行 |
| **AI 修复包** | 上传 ZIP 后自动弹出 | 源码 + 问题清单落盘 + 本地链接，直接交给 AI | `ext/lp_scan_server.py` |
| **ARTEX 集成** | 侧边栏「ARTEX」 | LLM 自治渗透，全屏内嵌，一键同起 | `boot.js` 350 行 |
| **Windows 免装 Python** | — | 包内自带 Python 3.11 embeddable | — |

---

## 五、快速开始

### 5.1 下载

从 [Releases](https://github.com/GeWu-academy/LingOps-Enhanced/releases) 下载对应平台的包：

| 平台 | 文件 | 解压后目录 | 启动方式 |
|---|---|---|---|
| macOS (Apple Silicon) | `LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64.zip` | `LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64/` | `./start.sh` |
| Windows x64 | `LingOps-AWD-AWDP-Enhanced-v1.3.3-win64.zip` | `LingOps-AWD-AWDP-Enhanced-v1.3.3-win64/` | 双击 `start.bat` |

> Windows 包**内置便携版 Python 3.11**（`python/` 目录，34 个文件），不用装 Python、不用 pip。
> 想用自己装的：删掉 `python\` 目录，`start.bat` 会自动退回 `python` → `py -3`。

### 5.2 启动

```bash
# macOS
unzip LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64.zip
cd LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64
./start.sh
```

**不要**直接在家目录执行 `./lingops-server` —— 它会去 `~/configs`、`~/`、`/etc/lingops` 找配置，找不到就报：

```
Failed to load config: failed to read config:
Config File "config" Not Found in "[/Users/shu/configs /Users/shu /etc/lingops]"
```

`start.sh` 会先 `cd` 到脚本所在目录，所以没问题。

### 5.3 访问

打开 <http://127.0.0.1:12800>，账号 **`admin` / `admin123`**（首次登录后请改）。

| 服务 | 端口 | 必需 | 说明 |
|---|---|---|---|
| 主服务 | 12800 | ✅ | Go 二进制，官方前端 + 注入层 |
| 扩展后端 | 12801 | 推荐 | 端口/上传点扫描、Flag 猎手、AI 修复包 |
| ARTEX | 8787 | 可选 | LLM 自治渗透 |
| PostgreSQL | 5433 | 可选 | ARTEX 的数据源 |

停止：`./stop.sh`（Windows 用 `stop.bat`，按端口 12800 / 12801 杀进程，不用记 PID）。

### 5.4 分步启动

```bash
./start.sh                # 全部启动（主服务 + 扩展 + ARTEX）
./start.sh --no-ext       # 只启动主服务
./start.sh --no-artex     # 不启动 ARTEX
bash start-ext.sh         # 只启动扩展后端（默认 12801）
bash start-ext.sh 12901   # 自定义端口
```

扩展后端自检：

```bash
curl http://127.0.0.1:12801/api/health
# {"ok": true, "version": "1.0.0", "jobs": 0}
```

---

## 六、架构：扩展是怎么挂上去的

官方只发布**编译好的二进制**和**打包好的前端**，没有源码，无法重新编译。

但官方前端有个特性：**运行时从磁盘读文件**。

- `frontend/dist/index.html` 每次请求都重新读取 → 可以注入 `<script>`；
- `frontend/dist/assets_v2/` 下任意文件都能被静态访问 → 可以放自己的页面和脚本。

所以整个扩展链路是：

```
浏览器请求 /
   ↓
lingops-server 读 frontend/dist/index.html
   ↓
<html> 里有一行：
   <script src="/assets_v2/lp-ext/boot.js?v=23" defer></script>
   ↓
boot.js 执行：
   ├── 往侧边栏塞「端口扫描」「ARTEX」两个菜单项
   ├── 隐藏官方自带的空「团队」占位菜单
   └── 点菜单 → 全屏 iframe 加载 panel.html
   ↓
panel.html 与主页面同源（都是 127.0.0.1:12800）
   → 能直接读 localStorage["lingops_token"]
   → 能调 /api/v1/assets 实现「从资产库导入目标」
   → 能调 /api/v1/assets 把扫描结果写回资产库
   ↓
扫描等重活交给独立进程 ext/lp_scan_server.py（12801，纯标准库）
```

**关键点**：官方二进制完全没动。升级官方版本时替换 `frontend/` 会覆盖 `index.html`，扩展失效，重新执行注入即可（见 `ext/uninstall.sh` 的注释）。

### 6.1 为什么用 `display:none` 藏菜单而不是删节点

侧边栏是 React 渲染的。手动 `removeChild` 会让 React 后续卸载时抛 `NotFoundError: Failed to remove child`。`display:none` 对 React 透明，且 `watchDom` 会在 React 重渲染后自动补一次。

### 6.2 官方菜单没有 `<a href>`

官方用 antd Menu 的 `items` API 渲染：

```js
{path:"/team", title:"团队", icon:"TeamOutlined"}
// 渲染成 <li class="ant-menu-item"><span>团队</span></li>
```

**没有 `<a href="/team">`**，所以选择器只能按 `.ant-menu-item` 的 `textContent` 匹配。

---

## 七、目录结构

```
LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64/
├── lingops-server              # 官方 Go 二进制（未修改，22 MB）
├── start.sh / stop.sh          # 一键启动 / 停止（macOS）
├── start.bat / stop.bat        # 一键启动 / 停止（Windows）
├── start-ext.sh                # 只启动扩展后端
├── configs/config.yaml         # 配置（端口、JWT 密钥、数据库）
│
├── frontend/dist/              # 官方前端 + 注入层
│   ├── index.html              #   ← 注入了一行 boot.js
│   └── assets_v2/
│       ├── index-BHVRK_eZ.js   #   官方 SPA bundle（只读）
│       └── lp-ext/             #   ← 本仓库写的扩展前端
│           ├── boot.js         #     注入入口：菜单 + iframe + 隐藏官方占位
│           ├── panel.html      #     扫描面板
│           ├── awdpplus.js     #     深度审计引擎（2078 行 / 331 条规则）
│           ├── flaghunt.js     #     Flag 查找
│           ├── trojanplus.js   #     免杀生成器 v1/v2
│           └── fsfix.js        #     Windows 文件管理器修复
│
├── ext/                        # 扩展后端
│   ├── lp_scan_server.py       #   2844 行，纯标准库，零 pip 依赖
│   ├── tools/                  #   check_fixed.py / make_patch.py / extract_files.py
│   └── uninstall.sh            #   一键卸载扩展
│
├── artex/                      # ARTEX 二进制 + skills
│   ├── artex                   #   官方二进制（未修改，37 MB）
│   ├── skills/                 #   api-recon / playwright-cli
│   └── config.example.json     #   配置模板（真配置在 .gitignore 里）
│
├── tests/awdp-corpus/          # 88 个回归样本
│   ├── run.js                  #   直接 node run.js，不需要浏览器
│   ├── corpus/vuln/            #   34 个真漏洞（6 种语言）
│   ├── corpus/safe/            #   27 个安全写法
│   ├── corpus/adversarial/     #   15 个对抗样本
│   ├── corpus/regress/         #   12 个回归样本
│   └── oracle/mask-audit.js    #   屏蔽层自测（会重新编译每个文件）
│
├── docs/                       # 23 章中文教程，5000+ 行
├── data/                       # 运行时 SQLite（.gitignore）
└── CHANGELOG.md                # 每处改动的原因
```

---

## 八、部署前必改

仓库里**不含**任何运行时数据或密钥，clone 下来需要自己生成：

| 项 | 处理方式 |
|---|---|
| `configs/config.yaml` 的 `auth.jwt.secret` | 换成随机串：`openssl rand -hex 32` |
| `artex/config.json` | 首次运行 `start.sh` 会从 `config.example.json` 生成，**填上 `database.password`** |
| `artex/jwt.key` | 首次运行自动生成，勿外传 |
| `data/lingops.db` | 首次启动自动建库并写入内置知识库 |

以下已进 `.gitignore`，**永远不要提交**：

```
data/             # 真实资产 IP、WebShell 凭据、admin 密码哈希
artex/data/       # MITM CA 私钥（mitmproxy-ca.pem）+ 抓包流量
artex/jwt.key     # ARTEX 的 JWT 签名密钥
artex/config.json # PostgreSQL 口令
```

> `artex/data/traffic/_ca/mitmproxy-ca.pem` 是**中间人证书私钥**。公开了，别人能拿它解密任何信任过这台机器的 HTTPS 流量。

---

## 九、自测与回归

### 9.1 深度审计引擎

改 `awdpplus.js` 前后都跑一遍，防止「修一个漏报换来三个误报」：

```bash
cd tests/awdp-corpus
node run.js          # 汇总，退出码 0=全绿 / 1=有回归
node run.js -v       # 逐文件看命中 / 漏报 / 误报
node run.js --json   # 机器可读
```

当前基线：

```
真漏洞     34/34 = 100.0%
安全代码   27/27 = 100.0%
回归       12/12 = 100.0%
新型漏洞   17/17 = 100.0%
对抗语料   14/15 =  93.3%   （x08 为已知盲区）
```

### 9.2 屏蔽层自测

深度审计的第一段是「抹掉注释和字符串」，抹多了就必然漏报，而 `node --check` 查不出这种错。`mask-audit.js` 会把每个文件屏蔽后**再编译一遍**，编译不过就是抹多了：

```bash
node tests/awdp-corpus/oracle/mask-audit.js tests/awdp-corpus/corpus
```

v1.3.1 靠它抓出 5 个这类 bug（Python `//` 整除被当注释、JS 正则字面量里的引号、JS 嵌套模板字符串、PHP shebang、PHP heredoc 里的 `/*`）。

### 9.3 语法检查

```bash
node --check frontend/dist/assets_v2/lp-ext/boot.js
python3 -m py_compile ext/lp_scan_server.py
bash -n start.sh
```

---

## 十、已知限制

- **ARTEX 需要 PostgreSQL 16**：`start.sh` 只负责启动不负责安装。macOS 用 `brew install postgresql@16`；
- **ARTEX 需要配 LLM**：不配模型不会真正跑任务；
- **端口扫描需要靶机可达**：扩展后端跑在本机，扫内网要保证网络通；
- **Windows Defender** 可能对未签名的 `python.exe` 报「未知发布者」，点「仍要运行」；
- **浏览器缓存**：12800 的响应没有 `Cache-Control`，改完前端要 **⌘⇧R 硬刷新**才生效；
- **官方 `/team`** 是空占位页（「功能正在开发中」），已由注入层隐藏，直接访问会回首页；
- **官方升级会覆盖注入**：替换 `frontend/` 后扩展失效，重新注入即可。

---

## 十一、免责与致谢

### 授权

- 原项目：[zhanglinglingc/lingops](https://github.com/zhanglinglingc/lingops) v0.2.0
- `lingops-server`、`artex/artex` 二进制**原样来自官方 release**，未做任何修改；
- 上游仓库**未声明开源许可证**，二进制版权归原作者所有。此处仅作学习与竞赛使用，**请勿商用**；
- 本仓库自行编写的部分（`ext/`、`frontend/dist/assets_v2/lp-ext/`、`docs/`、`tests/`、启动脚本）可自由使用。

### 用途限制

⚠️ **本项目仅可用于授权的靶场、CTF / AWD 比赛和你自己的测试环境。**

木马生成、WebShell 管理、漏洞利用这些功能，用在未授权的系统上属于违法犯罪。使用者自行承担全部法律责任。

### 变更记录

见 [CHANGELOG.md](CHANGELOG.md)。当前版本 **v1.3.2**。

完整教程见 [`docs/README.md`](docs/README.md)（23 章，5000+ 行）。
