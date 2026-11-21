# 23 · ARTEX 自治渗透（内嵌集成）

> ARTEX 是第三方开源的 **LLM 多智能体自治渗透系统**（Go 单二进制 + 内嵌 Next.js 前端 + PostgreSQL），
> 和 LingOps 是两个独立进程。本章讲的是**把它们一起用**：`start.sh` 一键拉起，LingOps 侧边栏点「ARTEX」
> 直接在内嵌窗口里操作，不用来回切标签页。

- 上游：`github.com/jiwoochris/artex-global`（0.3.15-global.1）
- 集成方式：**侧边栏菜单 + 全屏 iframe 内嵌**，无源码改动、无后端耦合
- 默认地址：<http://127.0.0.1:8787>
- 登录账号：`admin` / `admin123` —— **界面上只输密码**（用户名不用填），见下文「登录」

> ⚠️ **合法使用声明**：ARTEX 会自主发起扫描与利用，**只能对你自己拥有、或已取得书面授权的资产使用**。
> 未经授权对第三方系统进行探测/利用属违法行为。默认监听 `127.0.0.1`，不要随手改成 `0.0.0.0`。

---

## 一、目录与端口

集成后发布包多了一个 `artex/` 目录：

```
LingOps_v0.2_darwin_arm64/
├── lingops-server        # LingOps 主服务 12800
├── ext/                  # 扩展服务 12801
├── artex/                # 【新增】ARTEX 运行时
│   ├── artex             # 主程序（darwin/arm64，37MB）
│   ├── config.json       # 数据库/语言配置
│   ├── skills/           # api-recon / playwright-cli / scopesentry
│   ├── data/             # 流量记录（SQLite），可删
│   └── jwt.key           # 首次运行自动生成，勿外传
├── start.sh              # 一键启动 4 个服务
└── stop.sh               # 一键停
```

| 端口 | 服务 | 说明 |
|---|---|---|
| 12800 | LingOps 主服务 | 侧边栏所在 |
| 12801 | LingOps 扩展服务 | 端口扫描 / 上传点 / AI 修复包 |
| **8787** | **ARTEX Web UI** | 侧边栏「ARTEX」内嵌的就是它 |
| **8788** | **ARTEX 抓包代理** | ARTEX 自己起的目标流量代理（可不用） |
| **5433** | **PostgreSQL** | ARTEX 的唯一数据源，`start.sh` 会自动拉起 |

> ARTEX **不能没有 PostgreSQL**。缺失时报错：
> `open stores: database configuration not found`。

---

## 二、一键启动

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
./start.sh
```

正常输出里能看到四行就对了：

```
[LingOps] 已启动: http://127.0.0.1:12800
[扩展]   已启动: http://127.0.0.1:12801
[ARTEX]  PostgreSQL 已启动 (:5433, 日志 /tmp/lingops-pg.log)
[ARTEX]  已启动: http://127.0.0.1:8787  (日志 /tmp/lingops-artex.log)
```

只想要 LingOps、不要 ARTEX：

```bash
./start.sh --no-artex
```

全部停止（含 PostgreSQL）：

```bash
./stop.sh
```

日志位置：

- `logs/lingops-artex.log` — ARTEX 主日志（**首次的 setup token 在这里**，项目 logs 目录需保持 0700 权限）
- `logs/lingops-pg.log` — PostgreSQL 日志

### 首次使用需要装 PostgreSQL

`start.sh` 只会「启动」已经装好的 PostgreSQL，**不会自动安装**。没装的话先：

```bash
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1   # 国内网络必备，否则 brew 会卡在 git fetch
brew install postgresql@16
```

首次初始化数据库（只做一次）：

```bash
mkdir -p logs && chmod 700 logs
/opt/homebrew/opt/postgresql@16/bin/initdb -D /opt/homebrew/var/postgresql@16   # 若目录已存在则跳过
/opt/homebrew/opt/postgresql@16/bin/pg_ctl -D /opt/homebrew/var/postgresql@16 -o "-p 5433" -l logs/lingops-pg.log start
# 安全加固：使用 -S -D -R 创建普通权限用户，禁止授予超级用户(-s)
/opt/homebrew/opt/postgresql@16/bin/createuser -p 5433 -S -D -R artex
/opt/homebrew/opt/postgresql@16/bin/psql -p 5433 -d postgres -c "ALTER USER artex PASSWORD 'artex_local_2026';"
/opt/homebrew/opt/postgresql@16/bin/createdb -p 5433 -O artex artex
/opt/homebrew/opt/postgresql@16/bin/psql -p 5433 -d artex -c "GRANT ALL ON SCHEMA public TO artex;"
```

> ⚠️ **安全提示**：请勿使用 `-s` 参数赋予 `artex` 超级用户权限，以遵循最小权限原则，防范潜在工具逃逸通过 PostgreSQL 的 `COPY ... PROGRAM` 执行宿主机系统命令。

用户名/密码/库名/端口要和 `artex/config.json` 里的 `database` 段一致；
想换端口就同时改 `config.json` 和 `start.sh` 顶部的 `PG_PORT`。

---

## 三、登录 / 密码

ARTEX 只有一个管理员账号，**登录页只有一个密码框**，用户名写死在前端 JS 里，界面上看不到也填不了。

本包已把账号名从 `ARTEX` 统一改成 `admin`（界面、前端、后端校验、JWT 全链路）：

| 项目 | 值 | 说明 |
|---|---|---|
| 账号 / 密码 | `admin` / `admin123` | 打开 8787 只填密码；界面显示 `admin` |
| 界面登录 | **只输密码 `admin123`** | 登录页没有用户名框，用户名由前端 JS 写死发送 |
| 前端登录 | `api.login("admin", …)` | 内嵌静态 JS 里写死的用户名已改 |
| 接口层的 `username` | `admin` | 后端登录校验已改，现在传 `ARTEX` 会 401 |

> 结论：**账号 `admin`、密码 `admin123`**。浏览器里只输密码；curl / 脚本要带 `"username":"admin"`。

### 密码（当前 = `admin123`）

密码存在 PostgreSQL `settings` 表的 `auth.password_hash`（bcrypt），三种改法：

```bash
# 方式 A：登录后 UI 里改（推荐）
# 方式 B：接口改（TOKEN 取自 /api/auth/login 返回的 token）
TOKEN=$(curl -s -X POST http://127.0.0.1:8787/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST http://127.0.0.1:8787/api/auth/change-password \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"old_password":"admin123","new_password":"新密码"}' 
# 方式 C：库里还没密码时，用环境变量直接设（start.sh 已默认 admin123）
ARTEX_ADMIN_PASSWORD='admin123' ./start.sh     # 密码至少 8 位
```

⚠️ `ARTEX_ADMIN_PASSWORD` **只在库里还没有密码时生效**，库已初始化时会被忽略。
要改密码用 A / B，或者直接改数据库：

```bash
H=$(python3 -c "import bcrypt;print(bcrypt.hashpw(b'新密码',bcrypt.gensalt(10)).decode())")
PGPASSWORD=artex_local_2026 psql -h 127.0.0.1 -p 5433 -U artex -d artex \
  -c "update settings set value='$H' where key='auth.password_hash';"
```

### 登录（容易踩的坑）

界面点登录只发密码；脚本调 API 要带 `username: "admin"`，只发 `password` 会 401：

```bash
curl -s -X POST http://127.0.0.1:8787/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'
# → {"token":"..."}   200
```

连续输错会限流（`429 {"error":"失败次数过多，请稍后再试"}`），
等一会儿或 `./stop.sh && ./start.sh` 重启（限流计数在内存里）。

### 账号名怎么改 / 怎么还原

`ARTEX` 这个名字藏在二进制里的**三处**，而且后端那份不是字符串常量——编译器把它内联成了
3 条 ARM64 立即数指令，所以 `grep -r ARTEX` 全文替换是**无效**的：

```
cmp  x4, #0x5                 长度必须 5
mov  x5, #0x5241              'A','R'
movk x5, #0x4554, lsl #16     'T','E'   → x5 = "ARTE"
cmp  w4, w5
ldrb w3, [x3, #0x4]
cmp  w3, #0x58                'X'
```

用包里的一键脚本（会改三处 + 自动重签名，幂等）：

```bash
python3 patch-artex-admin.py            # 改成 admin（默认）
python3 patch-artex-admin.py super      # 改成任意 5 个英文字母
python3 patch-artex-admin.py --revert   # 全部改回 ARTEX
./stop.sh && ./start.sh                 # 重启生效
```

| 改动点 | 位置 |
|---|---|
| 后端登录校验（3 个 32 位立即数） | 文件偏移 10764696 / 10764700 / 10764716 |
| 前端 `api.login("…", 密码)` | 静态 JS 里的 5 字节字面量 |
| JWT `sub`（界面显示的账号名） | 文件偏移 11953048 |

> ⚠️ macOS(arm64) 改完**必须** `codesign -s - -f artex` 重签名，否则进程被直接 SIGKILL、日志为空（脚本已自动做）。
> 名字必须正好 **5 个英文字母**（后端 `cmp x4,#0x5` 是写死的长度校验）。
> 换新版 ARTEX 二进制后偏移会变，脚本会报「不是 5 字母账号名」并退出，重新定位即可。

---

## 四、在 LingOps 里用 ARTEX

1. 浏览器打开 <http://127.0.0.1:12800>，**硬刷新**（`⌘⇧R`）让 `boot.js?v=20` 生效；
2. 左侧菜单最下面出现 **「ARTEX」**（在「端口扫描」下面）；
3. 点一下 → 全屏内嵌窗口，标题栏有 `ARTEX · 自治渗透` 和状态位：
   - 绿点「在线」= 8787 已通；
   - 红点「未启动」= 没起 ARTEX，按第二章启动；
4. 标题栏右侧三个按钮：
   - **重新加载** — iframe 卡住时点它；
   - **新窗口打开** — 弹出独立标签页（做长任务时推荐，内嵌窗口关掉不会中断任务，但页面状态会丢）；
   - **关闭** — 或按 `Esc`。

> 内嵌只是「把 8787 塞进 iframe」，**ARTEX 的所有功能、数据、日志都在它自己的进程里**，
> 关掉 LingOps 的窗口不影响已经跑起来的任务。

---

## 五、配置 LLM（不配就是空转）

ARTEX 靠 LLM 决策，没配模型时启动日志会写：

```
[engine] no LLM provider configured — engine idle until set via /api/llm or env
```

两种配法：

**① 环境变量（重启生效）**

```bash
export ANTHROPIC_API_KEY='sk-ant-...'      # 或
export OPENAI_API_KEY='sk-...'
./start.sh
```

**② UI 里配（推荐，可切多个模型）**

进 ARTEX → 设置 → 模型，填 Base URL / API Key / 模型名。
国内可用任何 OpenAI 兼容端点（把 Base URL 指到自己的中转/本地 vLLM、Ollama 均可）。

> 想用**本地模型**跑：Ollama 起 `ollama serve` 后，Base URL 填 `http://127.0.0.1:11434/v1`，
> 模型名填 `qwen2.5:14b` 之类。小模型跑自治渗透效果一般，建议至少 14B 且上下文 ≥32K。

### 5.1 挂着代理（Clash / Surge / FlClash）时必须填 Proxy

典型报错：

```
Post "https://tokenrhythm.studio/v1/chat/completions": dial tcp 198.18.0.137:443: i/o timeout
```

**`198.18.0.137` 不是对方服务器 IP**，而是 Clash 系（FlClash / Clash Verge / Surge）的
**fake-ip** 地址（`198.18.0.0/15` 是约定的假 IP 池）。链路是这样断的：

1. 代理软件把 DNS 劫持成 fake-ip，`tokenrhythm.studio` 解析成 `198.18.0.137`；
2. ARTEX 是 Go 程序，**`net/http` 不读 macOS 的「系统代理」设置**，只认 `HTTPS_PROXY`
   环境变量或 profile 里的 `proxy` 字段；
3. 于是它直接去 dial 这个假 IP，只有代理软件的 **TUN 模式**在接管时才能通；
   切节点 / 内核重启 / TUN 掉线的那几秒，就是 `i/o timeout`；
4. 而 `retry.connect.attempts` 默认是 **0**，一次超时就直接判 `model_error`，整个意图 blocked。

**两步修好**（都在 ARTEX → 设置 → 模型里）：

| 字段 | 填什么 | 作用 |
|---|---|---|
| Proxy | `http://127.0.0.1:7890`（填你自己代理的混合端口） | 走代理，彻底绕开 fake-ip，不再依赖 TUN 是否在线 |
| 重试 → connect | 次数 `3`、间隔 `1000` ms | 网络抖动时自动重连，不再一次超时全盘失败 |

另外**全局重试策略**默认是全 0，等于「一次失败就放弃」。在 ARTEX → 设置 → 重试策略里调成：

```
connect 3 次 / 1000ms   stream 2 次 / 1000ms   empty 2 次 / 1000ms
breaker 3 次            intent 2 次 / 1000ms
```

命令行改也行（`<id>` 换成 `select id from llm_profiles` 查到的值）：

```bash
# 1) 确认代理端口在听（7890 换成你的）
lsof -nP -iTCP:7890 -sTCP:LISTEN

# 2) 改 profile
export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"
PGPASSWORD=$(python3 -c "import json;print(json.load(open('artex/config.json'))['database']['password'])") \
psql -h 127.0.0.1 -p 5433 -U artex -d artex -c "
  update llm_profiles set proxy='http://127.0.0.1:7890',
    retry_connect_attempts=3, retry_connect_interval_ms=1000 where id=<id>"

# 3) 改全局重试策略（ARTEX 正在跑就改成走接口，见下面的验证脚本）
TOK=$(curl -s -X POST http://127.0.0.1:8787/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST http://127.0.0.1:8787/api/llm/retry-policy \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"connect":{"attempts":3,"interval_ms":1000},
       "empty":{"attempts":2,"interval_ms":1000},
       "stream":{"attempts":2,"interval_ms":1000},
       "breaker":{"attempts":3,"interval_ms":0},
       "intent":{"attempts":2,"interval_ms":1000}}'
```

改完在 UI 点一次「测试」，返回 `{"ok":true,"reply":"..."}` 就成了。

> **反向提醒**：填了 Proxy 之后，如果哪天**彻底退出**代理软件，7890 就没人听了，
> 报错会变成 `connection refused`。这时把 Proxy 清空即可（直连走真实 DNS）。
> 判断口诀：**代理开着就填 proxy，代理关了就清空**。
>
> **验证方法**（不启动任何扫描，只测连通性）：
>
> ```bash
> TOK=$(curl -s -X POST http://127.0.0.1:8787/api/auth/login \
>   -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' \
>   | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
> curl -s -X POST http://127.0.0.1:8787/api/llm/test -H "Authorization: Bearer $TOK" \
>   -H 'Content-Type: application/json' \
>   -d '{"provider":"openai","base_url":"https://tokenrhythm.studio/v1",
>        "model":"deepseek-v4.1-flash-1017","api_key":"<你的key>",
>        "proxy":"http://127.0.0.1:7890"}'
> ```
>
> 注意这个接口的字段名是 **`provider`**（不是 `format`）；写错会静默退回 anthropic，
> 报 `anthropic: status 404 ... 接口不存在`——那不是你的 Key 或 URL 有问题。

### 5.2 上游有安全内容审查时（`cyber_policy` / `stream error`）

典型现象：配置好后提问，几秒就回一条

```
openai-responses: stream error
```

**4 秒左右就失败、工具调用 0 次**——这不是网络、不是 Key、也不是 ARTEX 的 bug，
而是**上游模型服务商对内容做了网络安全审查，直接把请求拦了**。

判断方法（直接打上游，绕过 ARTEX）：

```bash
curl -sN -X POST "$BASE_URL/responses" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"'"$MODEL"'","input":"payload / exploit / getshell 测试","stream":true}' \
  | grep -E 'response.failed|cyber_policy|is_blocked'
```

命中审查时上游会回：

```json
{"type":"response.failed",
 "response":{"error":{"code":"cyber_policy","type":"invalid_request",
 "message":"This content was flagged for possible cybersecurity risk..."}}}
```

事件流里还会带 `openai_chatgpt_moderation_metadata` →
`cyber_security.is_blocked: true`。

**这类模型不能用来做安全测试**，换模型即可，不是配置问题。特征对照：

| 现象 | 含义 |
|---|---|
| 4 秒内失败、0 次工具调用、`stream error` | 大概率是上游内容审查 |
| 报 `cyber_policy` / `is_blocked: true` | 确认是上游审查，**换模型** |
| 报 `rate_limit_exceeded` | 上游限流，等一会儿或换号 |
| 报 `model_not_found` | 模型名在该账号下不可用 |

**切换默认模型**（ARTEX 的 active profile 用专门接口，改 `is_default` 字段没用）：

```bash
TOK=$(curl -s -X POST http://127.0.0.1:8787/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin123"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 看有哪些
curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:8787/api/llm/profiles

# 切到 id=1
curl -s -X POST http://127.0.0.1:8787/api/llm/profiles/active \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"id":1}'
# → {"ok":true}，日志会出现 LLM reapplied from active profile
```

> **`POST /api/llm/profiles` 是整体更新**（必须带全字段），只传 `id` + `is_default`
> 会报 `llm_profiles_format_check` 约束错误；切默认一律用 `/profiles/active`。
>
> 另外建议把被审查的模型设成 `pool_exclude = true`，否则主模型限流时故障转移会
> 自动跳到它，又报一次 `stream error`：
>
> ```sql
> update llm_profiles set pool_exclude = true where id = <被审查的id>;
> ```

---

## 六、内置 skills

`artex/skills/` 下三个：

| skill | 作用 |
|---|---|
| `api-recon` | 接口侦察：`extract_route_map.py`（扒路由）、`harvest_static.py`（抓静态资源里的接口）、`spider_mpa.py`（多页站爬虫）、`runtime_harvest.js` + `preload.js`（浏览器运行时抓 XHR）、`build_perm_tree.py`（权限树） |
| `playwright-cli` | 让 agent 直接驱动 Playwright 浏览器，做登录后操作/截图/取 DOM |
| `scopesentry` | 接 ScopeSentry 的 MCP 端点（`http://<主机>/mcp`），复用它的资产测绘结果 |

自定义 skill：往 `artex/skills/<名字>/` 放 `SKILL.md` + 脚本，重启后自动出现在 agent 可选列表里。

> **`skill_dir` 必须指向真实目录。** `config.json` 里 `"skill_dir": "./skills"`（相对路径按 **artex 进程的工作目录** 解析，`start.sh` 是 `cd artex/` 后启动的，所以就是 `artex/skills/`）。
> 上游 `config.example.json` 里默认写的是 `/opt/artex/skills`（Linux 绝对路径），在 macOS / Windows 上**不存在**，而 artex **不会报错**——只在日志里打一行 `[config] skill directory: /opt/artex/skills`，然后静默加载 **0 个技能**，界面上看不到 `api-recon` / `playwright-cli` / `scopesentry`。
> `start.sh` 会自愈（检测到该值就改成 `./skills` 并打印提示）；手工启动的话自己确认日志里那行是 `<你的安装目录>/artex/skills`。

---

## 七、数据在哪 / 怎么清

| 数据 | 位置 |
|---|---|
| 业务数据（资产、发现、对话、agent、设置） | PostgreSQL `5433` 库 `artex` |
| 抓包流量记录 | `artex/data/`（SQLite，可整个删，重启自动重建） |
| JWT 签名密钥 | `artex/jwt.key`（删掉会重新生成，所有已登录会话失效） |
| 运行日志 | `/tmp/lingops-artex.log` |

想彻底重置 ARTEX（**会丢所有扫描结果**）：

```bash
./stop.sh
rm -rf artex/data artex/jwt.key
/opt/homebrew/opt/postgresql@16/bin/dropdb -p 5433 artex
/opt/homebrew/opt/postgresql@16/bin/createdb -p 5433 -O artex artex
./start.sh
# 然后按第三章重新设密码
```

---

## 八、常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 侧边栏没有「ARTEX」 | `boot.js` 还是旧缓存。`⌘⇧R` 硬刷新；仍没有就确认 `frontend/dist/index.html` 里是 `boot.js?v=20` |
| 点开是白屏 / 「未启动」 | 8787 没起。`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/` 应为 200；不是就看 `/tmp/lingops-artex.log` |
| `open stores: database configuration not found` | 没 PostgreSQL 或 `config.json` 的 `database` 段缺失。按第二章装并初始化 |
| `database unavailable` | PG 没起或端口/密码不对。`lsof -nP -iTCP:5433 -sTCP:LISTEN` 确认；密码要和 `config.json` 一致 |
| 登录一直 401 | 账号 `admin` / 密码 `admin123`（界面只输密码）；脚本调 API 的 `username` 要写 `admin`，写 `ARTEX` 已无效 |
| 登录 429 | 连续失败限流。等几分钟或重启 ARTEX |
| 启动卡住不动 | `brew` 在跑 `auto-update`。`export HOMEBREW_NO_AUTO_UPDATE=1` 再装依赖 |
| 端口 8787 被占 | `lsof -nP -iTCP:8787 -sTCP:LISTEN` 找到旧进程 kill，或 `./stop.sh` |
| 任务一直不跑 | 没配 LLM。看日志有没有 `engine idle`，按第五章配 |
| agent 里看不到任何技能 / 技能列表是空的 | `config.json` 的 `skill_dir` 指向了不存在的路径（典型是上游模板里的 `/opt/artex/skills`）。日志 `[config] skill directory:` 那行必须是你机器上真实存在的 `.../artex/skills`；改成 `./skills` 后重启 |
| 启动日志 `[engine] no LLM provider configured` | 正常现象，不是报错。ARTEX 必须配 LLM 才能干活，按第五章配 |
| 提问后秒回 `model_error` / `dial tcp 198.18.0.x:443: i/o timeout` | 代理软件的 fake-ip。ARTEX 是 Go 程序，不读系统代理设置，直连假 IP 只有 TUN 在跑时才通。给 profile 填 `proxy`（如 `http://127.0.0.1:7890`）+ 开重试，见 **5.1** |
| 提问后 `anthropic: status 404 ... 接口不存在` | 模型格式被当成 anthropic 了。Base URL 是 OpenAI 兼容端点的话，确认格式选的是 OpenAI；`/api/llm/test` 的字段名是 `provider` 不是 `format` |
| `connection refused`（7890 之类） | profile 里填了 `proxy` 但代理软件已退出。清空 Proxy 字段即可 |

---

## 九、Windows / 其他平台

`artex/artex` 是 **darwin/arm64** 二进制，Windows 包（`LingOps_v0.2_win64_enhanced.zip`）里**不带**它。

Windows 上想用 ARTEX：

1. 从上游 Release 下载对应平台的 ARTEX（`artex-*-windows-amd64`）；
2. 解压到 LingOps 目录下，改名为 `artex/artex.exe`（`config.json`、`skills/` 一起放进去）；
3. 自备 PostgreSQL（或 `docker compose up -d` 起官方镜像），把 `config.json` 的 `database` 指过去；
4. 手动起：`artex\artex.exe -addr 127.0.0.1:8787`，然后照常用侧边栏菜单。

`start.sh` 里的 ARTEX 段只在 macOS/Linux 生效；Windows 用 `start.bat` 或手动起。

---

## 十、和 LingOps 的分工

| 场景 | 用谁 |
|---|---|
| 批量存活/端口/上传点扫描 | LingOps「端口扫描」（12801，快、轻、无 LLM 成本） |
| 已知目标、要打具体漏洞链 | LingOps AWDP Break/Fix + 深度审计 |
| 给一堆资产，让 AI 自己规划「先看什么、再打什么」 | **ARTEX** |
| 需要浏览器自动化（登录态、SPA、XHR 抓接口） | **ARTEX**（playwright-cli + api-recon） |
| 修漏洞、出补丁包 | LingOps「AI 修复包」+ `make_patch.py` |

简单说：**LingOps 负责「确定性的批量动作」，ARTEX 负责「需要判断的探索」**。
