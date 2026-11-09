# 变更记录

这个包是在官方 `LingOps v0.2.0`（darwin-arm64）基础上做的增强版。
官方二进制 `lingops-server` **未修改**，所有改动都在 `frontend/dist/` 注入层、`ext/` 扩展后端、`artex/` 与文档里。

格式：`[模块] 改了什么 —— 为什么改`

---

## v1.3.4 · 2026-11-10

### 深度审计规则库扩容：201 → 331 条

官方引擎只认「sink 参数里有污点变量」，规则再少就更容易漏。这版把规则库翻了一倍多，并补上 2021 年以后常见的反序列化 / 认证 / 解压类漏洞。

| 表 | v1.3.3 | v1.3.4 | 变化 |
|---|---|---|---|
| `SOURCES`（污点来源） | 66 | 66 | — |
| `SINKS`（危险函数） | 114 | **212** | +98 |
| `PATTERNS`（静态特征） | 21 | **53** | +32 |
| **合计** | **201** | **331** | **+130** |

新增规则类别：`nosqli`（NoSQL 注入）、`xpath`（XPath 注入）、`zip`（压缩包穿越）。

新增覆盖（节选）：

- **反序列化**：Jackson `autoTypeSupport` / `enableDefaultTyping`、Fastjson `JSON.parse*`、SnakeYAML `new Yaml()`、XStream `fromXML`、Newtonsoft `TypeNameHandling.*` / `SimpleTypeResolver`、C# `BinaryFormatter` / `LosFormatter` / `ObjectStateFormatter`、Python `torch.load` / `dill` / `yaml.load`、Ruby `Marshal.load` / `create_additions`
- **认证**：JWT `algorithms: ['none']`、`jwt.decode` 不验签、硬编码 `secret`、`alg` 取自请求头
- **注入**：MyBatis `${}` 拼接、NoSQL `$where` / `$ne` / `$regex`、XPath `xpath.compile` / `selectNodes`、LDAP `search` 拼接
- **解压穿越**：`zip-slip`（`ZipEntry.getName` / `extractall` / `ZipFile.extract`）、`tar-slip`
- **文件与命令**：`Path.Combine` 拼接请求参数、ASP `ADODB` 字符串拼接、Ruby `params.permit!`、`Open3` / `IO.popen` 包装
- **框架特征**：Spring `class.module.classLoader`（CVE-2022-22965）、SSTI（SpEL / Thymeleaf / FreeMarker）、模板注入（EJS / Pug / Handlebars / Nunjucks）
- **配置型**：`trust proxy`、CORS `credentials: true`、`HttpOnly=false`、`SameSite=None`、`allow_pickle=True`、`trust_remote_code=True`

新增语言识别：`.cs` → C#、`.asp` / `.aspx` → ASP。

### 引擎本身修了 3 处

规则加得再多，被通道挡掉也是白加：

1. **`LOW_CATS` 漏了新类别** —— 参数区里追不到污点的 sink 会被直接丢弃。补上 `nosqli` / `zip` / `xpath` 后，`$ne: null`、`ZipEntry.getName()` 这类写法才能出低置信提示。
2. **`PATTERNS` 没有语言作用域** —— `JSON.parse(` 在 Node.js 里是安全的内置函数，在 Java 里是 Fastjson RCE。给 `PATTERNS` 加了可选 `lang: [...]` 字段，规则不再跨语言误报。
3. **配置型特征走了错误的通道** —— `algorithms: ['none']`、`TypeNameHandling = TypeNameHandling.All` 这类写法没有「函数参数区」，sink 通道必然跳过。改由 `PATTERNS` 覆盖；同理 MyBatis 的 `@Select("... ${id}")` 特征写在字符串里，规则加了 `raw: true` 才能看到原始行。

### 回归

新增 `corpus/modern/` 套件 17 例（Fastjson、Jackson、SnakeYAML、XStream、Newtonsoft、JWT none、NoSQL、zip-slip、tar-slip、Spring4Shell、MyBatis、C# BinaryFormatter 等）。

```
真漏洞     34/34 = 100.0%
安全代码   27/27 = 100.0%
回归       12/12 = 100.0%
新型漏洞   17/17 = 100.0%
对抗语料   14/15 =  93.3%   （x08 为已知盲区）
```

---

## v1.3.3 · 2026-11-09

### 项目更名为 LingOps AWD/AWDP Enhanced

名字里补上 `AWD/AWDP`，让人一眼看出这是打什么场景的工具，不用点进 README 才知道。

| 项 | 旧 | 新 |
|---|---|---|
| README 标题 | LingOps Enhanced · 灵控增强版 | **LingOps AWD/AWDP Enhanced · 灵控攻防增强版** |
| macOS 包 | `LingOps_v0.2_darwin_arm64-enhanced.zip` | `LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64.zip` |
| Windows 包 | `LingOps_v0.2_win64_enhanced.zip` | `LingOps-AWD-AWDP-Enhanced-v1.3.3-win64.zip` |
| 解压后根目录 | `LingOps_v0.2_darwin_arm64/` | `LingOps-AWD-AWDP-Enhanced-v1.3.3-darwin-arm64/` |

> **GitHub 仓库 slug 仍是 `LingOps-Enhanced`** —— 改名需要仓库 admin 权限，当前账号在组织下只有 push，
> `PATCH /repos` 返回 404。等组织 owner 授权后可改，改名后旧 URL 会自动 301。

包内目录结构与启动方式完全不变，`start.sh` / `start.bat` 都是按脚本自身位置定位，不受根目录名影响。

---

## v1.3.2 · 2026-11-09

### Windows 包内置便携版 Python

`LingOps_v0.2_win64_enhanced.zip` 多了 `python/` 目录（Python 3.11.9 embeddable，34 个文件，包体积 9.6 → 20 MB），
对方机器**不用装 Python** 就能跑扩展后端：

| 项 | 说明 |
|---|---|
| `python/python.exe` | 便携解释器，自带 `vcruntime140.dll`，不写注册表、不碰 PATH |
| `python/python311._pth` | 追加 `..\ext`，让 `ext/` 里的同级模块能 import |
| `start.bat` | 查找顺序：包内 `python\python.exe` → `python` → `py -3`；都没有才退回「只启动主服务」 |

`ext/lp_scan_server.py` 只用标准库（27 个顶层 import 全部命中 embed 包，`http.server` / `ssl` / `_socket` 等已核验），
所以不需要 pip。darwin 包不变，`start.sh` 直接用 PATH 里的 `python3`（你的 `myenv` 会优先命中）。

### 移除「团队作战室」扩展

单人打 AWD 用不上，还要额外维护一个 SQLite 库和一层 12801 路由，**整体移除**：

| 删除 | 说明 |
|---|---|
| `frontend/dist/assets_v2/lp-ext/team.html` | 421 行，成员/靶机看板 + 全局时间线页面 |
| `ext/team_store.py` | 281 行，`data/team.db` 的数据层 |
| `ext/lp_scan_server.py` 里的 `/api/team` 路由与 `_send_team` | 后端不再有团队接口 |
| `boot.js` 里的 `openTeam()` / 侧边栏「团队」项 / 自动记账 `startTeamSync()` | 前端不再有入口，也不再每 10 秒轮询任务和 flag 历史 |
| `docs/24-team.md`、`data/team.db*` | 文档与运行时数据一并清掉 |

侧边栏现在只剩两项：**端口扫描**、**ARTEX**。

官方 SPA 还自带一个「团队」菜单（`{path:"/team",title:"团队"}`），点进去只有
「团队信息、成员管理等功能正在开发中...」。`boot.js` 里新增 `hideTeamMenu()` 一并隐藏
（按 `.ant-menu-item` 的文字匹配，因为 antd 用 items API 渲染、没有 `<a href>` 可认；
用 `display:none` 而不是删节点，避免 React 卸载时抛 `removeChild` 错），
直接访问 `/team` 会回首页。

官方 `/team` 页原样保留（本来就是占位页），要多人协作直接调 `/api/v1/users` 建账号，见 [13 章](docs/13-team-settings.md)。

版本号 1.3.1 → 1.3.2；`index.html` 的 `boot.js` 引用升 `?v=23`。

---

## v1.3.1 · 2026-11-09

### 屏蔽层（`stripComments`）五个漏报修复

这一版只干一件事：**注释/字符串的屏蔽不能多抹一个字**。抹多了就等于把真漏洞一起藏起来。

起因是新增的 `tests/awdp-corpus/oracle/mask-audit.js`（屏蔽正确性审计器）：
它把每个文件屏蔽后**再编译一遍**（`py_compile` / `node --check` / `php -l`），
编译不过就说明屏蔽层改坏了代码。拿 1500 个 Python、150 个 JS、110 个 PHP 真实文件一跑，
立刻抓出 5 个 bug —— 它们从 v1.0 起就存在，靠手写的 85 个样本永远发现不了。

| # | 触发写法 | 之前（漏报） | 现在 |
|---|---|---|---|
| 1 | Python `x = a // 2` | `//` 被当行注释 → 该行引号被截断 → 状态机卡在字符串里 → **后面整段代码被抹掉** | `//` 只在非 python/ruby 语言里算注释（python 是整除，ruby 是空正则） |
| 2 | JS `/[&<>"']/g` | 正则字面量里的引号开了字符串 → 失步 → 后续行全被抹 | 新增「正则字面量」状态：`\` 转义、`[...]` 字符类、闭合后吃 flags；`/` 是除号还是正则由前一有效字符判定 |
| 3 | JS `` `${a(`b`)}` `` | 内层反引号提前关掉模板 → `https://` 的 `//` 被当注释 → 模板后代码被抹 | 新增插值栈 `interpStack`：`${` 压栈回到代码态，`{}` 配平后弹回模板态，支持任意层嵌套 |
| 4 | PHP `#!/usr/bin/env php` | shebang 被抹成空格 → `declare(strict_types=1)` 不再首行 → 整文件 Fatal | 文件首行 `#!` 不算注释 |
| 5 | PHP heredoc `<<<SQL ... /var/*/logs ... SQL;` | heredoc 里的 `/*` 开了块注释 → **一路吃到文件末尾**，后面所有 sink 全被抹 | 新增 heredoc/nowdoc 状态：`<<<` + 标签进入，按标签行退出，内容抹成空格但保留换行 |

> 前 4 个是「状态机失步」，第 5 个是「heredoc 根本没被识别」。
> 共同后果都一样：**真实的 `system()` / `exec()` / `readfile()` 被抹掉 → 扫描报 0 条**。

### 新增 `tests/awdp-corpus/oracle/mask-audit.js`

屏蔽层单独可测了，不用再靠「扫描结果看着不对」来猜。

```bash
node tests/awdp-corpus/oracle/mask-audit.js <目录或文件> [-v] [--json] [--cap N] [--no-compile]
```

三道独立检查：

1. **行数守恒** —— 屏蔽前后行号必须一一对应（否则报出来的行号全错）；
2. **屏蔽后还能编译** —— `py_compile` / `node --check` / `php -l`，不过就是抹多了；
3. **整行被抹清单** —— 列出被整行抹成空白的行，供人工确认那些确实是注释。

单行超过 2000 字符的文件（压缩/混淆代码）里 `/` 是除号还是正则**不可判定**，
这类文件编译失败单独归为 `minified`，不计入结构性问题。

### 新增回归样本（`corpus/regress/`，9 → 12）

`r11_py_floordiv.py`、`r12_js_regex_quote.js`、`r13_php_heredoc.php` —— 每个都锁死上面一个 bug，
用旧引擎跑必 FAIL，用新引擎跑必命中。

### 其它

- `run.js --json` 的输出不再被引擎加载时的版本行污染（require 期间 stdout 临时改道 stderr）；
- 版本号 1.3.0 → 1.3.1（`boot.js` 同步升 `?v=12`）；
- 20 章、`tests/awdp-corpus/README.md` 补 `mask-audit.js` 用法。

### 验证基线

```
node tests/awdp-corpus/run.js
  真漏洞 34/34、安全代码 27/27、回归 12/12、对抗 14/15（1 个已文档化盲区）  exit 0

mask-audit（真实代码）
  Python 1500 文件  行数错位 0  编译失败 0
  JS      150 文件  行数错位 0  编译失败 0（1 个压缩代码跳过）
  PHP     110 文件  行数错位 0  编译失败 0
```

---

## v1.3.0 · 2026-11-09

### AWDP 深度审计引擎（`frontend/dist/assets_v2/lp-ext/awdpplus.js`）

这一版只干一件事：**让「已净化」判定不能被诱饵骗**。

| 改动 | 之前 | 现在 |
|---|---|---|
| 净化结果必须真的流到 sink | `$p = realpath($f); readfile($f);` 判为已净化（假安全） | 报高危（`realpath` 的结果没进 `readfile`） |
| 污点源与 sink 跨行时同样检查 | `const u = new URL(req.query.u); fetch(req.query.u);` 判为已净化 | 报 SSRF 高危 |
| 回看窗口不再因「有污点源」整体关闭 | `$real = realpath($root . $f); readfile($real);` 被误报 | 正确判为已净化 |
| 字符串拼接构造的 sink | `executeQuery("... " + id)` 只报低置信 | 升级为高危（拼接本身就是注入面） |
| 新增 `lingops:ignore` 抑制标记 | 无（误报只能忍着或改代码） | 命中行/上一行带标记即跳过，汇总显示「已忽略 N 条」 |
| 版本号 | 1.2.0 | 1.3.0（`boot.js` 同步升 `?v=11`） |

**新增回归自测**（`tests/awdp-corpus/`，85 个已知答案样本）：

```bash
node tests/awdp-corpus/run.js       # 退出码 0 = 全绿
node tests/awdp-corpus/run.js -v    # 逐文件看命中/漏报/误报
```

当前基线：真漏洞 34/34、安全写法 27/27、回归 9/9、对抗 15 个里 14 个命中高危
（`x08` 是已文档化的盲区：`obj[k]=v` 与 `arr[i]=x` 无类型信息时不可区分）。

### 文档

- 20 章新增「十、误报怎么处理（`lingops:ignore`）」「十一、自己验证引擎（回归自测）」两节；
- 20 章「已知边界」补两条：净化必须真的流到 sink、原型污染只做到低置信；
- 新增本文件 `CHANGELOG.md`。

---

## v1.2.0 · 2026-11-08

### AWDP 深度审计引擎

针对「拖进去 0 条 / 只报几条无关紧要的」修的 7 类静默漏报：

1. Node 侧只认 `req.query / req.body`，Next.js / Fastify / NestJS 全 0 条 → 补 Web Fetch API、`new URL().searchParams`、装饰器参数；
2. `LIBXML_NOENT` 被当成净化函数 → PHP XXE 永远看不到 → 移除，改为静态规则直接报；
3. `codeOnly` 把字符串内容整段抹掉 → Ruby `#{}`、PHP `"$id"`、Python f-string 里的变量全丢 → 改为只抹内容、保留插值；
4. 参数区有标识符但追不到污点 → 静默丢弃 → 新增低置信兜底（可开关）；
5. 无 Node 侧 XXE 规则 → 补 `--noent`、`libxmljs`、`xmllint`；
6. NestJS 装饰器参数、对象解构未识别 → 补 `declTargets`；
7. Ruby `params[:c]` 中转后漏报 → 同 3。

### 其它

- 修复两条正则用 `\b` 导致的误报：`\b` 在 `.` 之后成立，`re.compile(` / `subprocess.run(` 这类库调用被误判成代码编译/命令执行；
- 修正则后正则改为 `(?<![.\w])` 负向后视。

---

## v1.1.0 · 2026-11-07

### 新增扩展模块

| 模块 | 入口 | 说明 |
|---|---|---|
| 端口 / 上传点扫描 | `12801` + `/port-scan` | 官方只能扫 IP 存活，扩展补端口发现 + 上传点探测 |
| Flag 查找 | `/flag` 页注入 | 官方只能填一个固定路径，扩展做全盘搜索 |
| 免杀木马 | `/attack/trojan` | 官方 12 个明文模板过不了查杀，扩展做三档混淆 + 图片马 + Godzilla |
| AWDP 深度审计 | `/awdp/break`、`/awdp/fix` | 跨行污点分析，补官方引擎漏报，可对比官方结果 |
| AI 修复包 | 上传 ZIP 后 | 源码 + 问题清单落盘到 `~/LingOps-AWDP/<id>/`，直接交给本地/在线 AI 修 |
| 团队作战室 | 侧边栏「团队」 | 分工看板 + 全局作战时间线 + 一键导出复盘 Markdown |

### ARTEX 集成

- `artex-0.3.15` 内嵌到侧边栏，`start.sh` 一键同起 PostgreSQL(5433) + ARTEX(8787) + LingOps(12800) + 扩展(12801)；
- 账号统一为 **`admin` / `admin123`**，界面只输密码（无需登录 ARTEX 后改密）；
- 界面全链路汉化；
- ARTEX 自带脚本修掉 17 条 + 13 条审计问题（`skills/api-recon/scripts/`），误报的加 `lingops:ignore` 并写明理由。

### 文档

- 24 篇功能教程（`docs/01` – `docs/24`），覆盖每个功能的操作步骤、坑、验证方法；
- 官方已知问题（Windows WebShell 盘符、ARTEX 缺 PostgreSQL 等）写进 `docs/README.md` 的 FAQ。

---

## 与官方 v0.2.0 的差异一览

| 文件/目录 | 是否改动 | 说明 |
|---|---|---|
| `lingops-server` | ❌ 未改 | 官方二进制原样 |
| `frontend/dist/index.html` | ✅ | 注入 `boot.js` 与各扩展入口 |
| `frontend/dist/assets_v2/lp-ext/` | ✅ | 扩展前端（`awdpplus.js`、`boot.js`、各页面） |
| `ext/` | ✅ | 扩展后端（`12801`） |
| `artex/` | ✅ | 内嵌 ARTEX + 汉化 + 账号改动 |
| `docs/` | ✅ | 24 篇教程 |
| `tests/awdp-corpus/` | ✅ | 引擎回归语料 + `run.js` + `oracle/mask-audit.js`（屏蔽层审计） |
| `configs/` | ❌ 未改 | 官方默认配置 |

---

## 怎么确认「我拿到的是改过的包」

```bash
grep -o "v1\.[0-9]\.[0-9]" frontend/dist/assets_v2/lp-ext/awdpplus.js | head -1   # 应为 v1.3.2
grep -o "awdpplus.js?v=[0-9]*" frontend/dist/assets_v2/lp-ext/boot.js             # 应为 ?v=12
grep -c "团队作战室" frontend/dist/assets_v2/lp-ext/boot.js                        # 应为 0
node tests/awdp-corpus/run.js                                                    # 退出码 0
```

四条都过，才是这一版。
