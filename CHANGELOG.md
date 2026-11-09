# 变更记录

这个包是在官方 `LingOps v0.2.0`（darwin-arm64）基础上做的增强版。
官方二进制 `lingops-server` **未修改**，所有改动都在 `frontend/dist/` 注入层、`ext/` 扩展后端、`artex/` 与文档里。

格式：`[模块] 改了什么 —— 为什么改`

---

## v1.3.6 · 2026-11-10

### 收录 2020–2026 年真实 CVE

v1.3.5 的漏洞知识库有 147 条，但绝大多数是按漏洞类型写的通用条目，缺少具体 CVE。这版直接对接 NVD API 2.0 采集 2020–2026 年的真实 CVE，并配了一批 CVE 家族扫描规则。

| 内容库 | v1.3.5 | v1.3.6 | 变化 |
|---|---|---|---|
| 漏洞知识库 | 147 | **1047** | +900（全部来自 NVD） |
| 扫描规则 | 634 | **759** | +125 |

#### 采集方式（可复现）

`ext/tools/cve_harvest.py` 是完整采集管道，不是一次性脚本：

```bash
python3 ext/tools/cve_harvest.py --year-from 2020 --year-to 2026 --cap 900
```

- 数据源：`https://services.nvd.nist.gov/rest/json/cves/2.0`，97 个关键词（PHP / Java / Node / Python / Go / 中间件 / 安全设备 / 国产 OA）
- **只收录 NVD 真实返回的 CVE 号**，编号、CVSS、CWE、受影响版本、摘要全部来自 NVD 原始响应，不做任何推测补全
- 每条带 NVD 详情页链接 + 厂商公告链接
- 本地缓存 `.cache/nvd/`，`--resume` 可离线重跑
- 限速 6.2s/请求（无 API key 约 5 次/30 秒）

#### 条目质量

- **年份**：2020 / 2021 / 2022 / 2023 / 2024 / 2025 / 2026 全覆盖
- **类型**：21 类，XSS / SSRF / XXE / 文件上传 / SSTI / 反序列化 / 注入 / 越权 / 认证绕过等都有，单类型占比上限 18%（避免信息泄露类淹没整个库）
- **CWE 映射**：65 条 CWE → 中文类型映射，纯 DoS 类（CWE-400/674/770 等）直接丢弃（AWD 场景无利用价值）
- **严重度阈值**：通用漏洞 CVSS ≥ 7.0；XSS / SSRF / XXE / 上传 / SSTI / 反序列化等 AWD 高频类型放宽到 6.0

#### 新增 125 条 CVE 家族扫描规则

`ext/tools/awdp-lib-gen/gen5_cve_rules.py` 按语言 × CVE 家族生成，全部通过 Go RE2 编译校验（官方扫描器用 Go regexp，不支持 lookahead，历史上有多条规则因此静默失效）：

- PHP：CVE-2024-4577 / 8926 CGI 参数注入、CVE-2019-11043 FPM、ThinkPHP 多版本 RCE、Laravel APP_KEY 反序列化、phar
- Java：Log4Shell、Spring4Shell、Spring Cloud Gateway / Function、Struts2、Shiro、Fastjson / Jackson、Tomcat AJP、WebLogic T3
- Node：原型污染 → RCE、`node-serialize`、JWT 缺陷、EJS / Handlebars SSTI
- Python / Go / Ruby / C#：`yaml.load`、`pickle`、`torch.load`、GORM 拼接、`Marshal.load`、`BinaryFormatter`
- 中间件与国产 OA：Nacos、Confluence OGNL、Jenkins、GitLab、通达 / 致远 / 泛微 / 用友

#### 前端

- 规则列表「来源」筛选新增 **CVE 采集** 项，可把这 125 条 CVE 家族规则和官方内置规则分开看
- 知识库 / 规则列表拉取上限从 500 提到 3000，否则条目破千后前端会截断

> 官方后端在加载 `data/poc/*.json` 时会把 `source_type` 一律改写成 `builtin`，所以「CVE 采集」是按 `rule_id` 前缀 `x3-` 识别的，不依赖 `source_type` 字段。

#### 修了一个分发层面的 bug

官方后端按 **bool** 反序列化 `is_active` / `is_builtin`，而数据库里存的是 `1` / `0`。`awdp_lib.py export` 之前直接把 DB 里的整数写进种子 JSON，导致**全新安装时整个 fix-library 加载失败**：

```
Warning: Failed to load fix library: json: cannot unmarshal number into Go struct field .knowledge.is_active of type bool
```

服务端只打一行 warning 就继续跑，表现是知识库和规则都是空的。现在导出时统一转成 `true` / `false`，已在纯净目录实测：新装即可看到 1047 条知识 / 759 条规则。

#### 说明

CVE 条目的 `exploit_tip` / `fix_*` 是按 **CWE 类型的通用打法** 生成的，不是针对该 CVE 验证过的利用步骤；具体利用请以 NVD 与厂商公告为准。CVE 条目本身不带 `match_rules`，不产生扫描规则（扫描规则由上面那 125 条单独提供）。

---

## v1.3.5 · 2026-11-10

### AWDP 五个内容库全面扩容

`/awdp/break`（Payload 构造、漏洞利用、WAF 绕过）和 `/awdp/fix`（漏洞知识库、扫描规则）这五块原来是官方自带的样例量，真打比赛不够用。这版按「先联网调研、再逐条核实」的方式补到能直接上手。

| 内容库 | v1.3.4 | v1.3.5 | 变化 |
|---|---|---|---|
| Payload 构造 | 26 | **110** | +84 |
| 漏洞利用 | 21 | **53** | +32 |
| WAF 绕过 | 24 | **73** | +49 |
| 漏洞知识库 | 81 | **147** | +66 |
| 扫描规则 | 335 | **634** | +299 |

#### 新增覆盖

- **PHP（含近期 CVE）**：CVE-2024-4577 / CVE-2024-8926（CGI 参数注入）、CVE-2019-11043（FPM 下溢）、CVE-2024-2961（glibc iconv → `php://filter` 链）、phar 反序列化、FPM 未授权 FastCGI、动态函数调用、弱类型比较、变量覆盖、日志投毒写 shell、CRLF
- **Java**：Spring4Shell、Spring Cloud Gateway SpEL、Spring Cloud Function、Actuator、Struts2 OGNL、Shiro 默认密钥、Log4Shell、Fastjson / Jackson 链、Tomcat AJP Ghostcat 与 2025 写入竞争、WebLogic T3、JNDI
- **Node / Go / Ruby / C#**：EJS / Handlebars SSTI、原型污染 → RCE、`node-serialize`、JWT 缺陷、ORM 注入；Go `text/template`、GORM 拼接、zip slip、SSRF；Ruby `Marshal.load`、`YAML.load`；C# ViewState / `BinaryFormatter`
- **通用 Web**：LDAP / XPath 注入、开放重定向、请求走私、条件竞争、CORS / CSRF、会话固定、IDOR、上传解析链、Redis / MySQL / PostgreSQL / Mongo / Docker / K8s 未授权、GraphQL、SSRF → gopher 内网链
- **WAF 绕过**：按「编码层 / 语法层 / 协议层 / 业务层」四层归类，覆盖大小写、注释、双重 URL、Unicode、`multipart`、`chunked`、`HPP`、`Content-Type` 混淆、国内厂商（安全狗 / D盾 / 宝塔 / 云锁 / 雷池）的常见特征
- **扫描规则**：PHP / Java / Python / Node / Go 的危险 sink 与框架指纹，以及 ThinkPHP、Laravel Ignition、PHPUnit `eval-stdin`、Spring Boot Actuator、nginx alias / `merge_slashes` / 备份后缀、`.env`、`.git`、Swagger、Jolokia、Druid、Nacos 等可直接命中的特征

#### 修掉的问题

- **4 条正则规则一直没生效**：`deser-py-002`、`pickle-py-002`、`xxe-java-001`、`xp-type-inarray` 用了 `(?!...)` 负向先行断言，而 Go 的 RE2 引擎不支持，规则编译直接失败、静默不参与扫描。已改写成等价的可编译形式。全部 541 条正则规则现在都能通过 RE2 编译校验。
- **新增规则全部规避 lookahead / 反向引用**，避免重蹈覆辙。

#### 工具与工程

- 新增 `ext/tools/awdp_lib.py`：内容库三方同步（`export` / `import` / `sync` / `stats`），保证 SQLite 与随包发布的 `data/poc/*.json` 种子始终一致；顺手修了时间戳写成字面量、`references` 是 SQL 关键字、`item_id` 字段名不统一等问题
- 新增 `ext/tools/patch_labels.py`：给官方 bundle 补新分类 / 新语言的中文标签，幂等、可重复执行
- 新增 `ext/tools/awdp-lib-gen/`（内容生成脚本）与 `ext/tools/awdp-lib-extra/`（扩充数据源），内容可复现、可增量维护
- `.gitignore` 放行 `data/poc/*.json`（内容库种子必须入库），`data/lingops.db` 仍然禁止

#### 前端

- 补 12 个新分类标签（任意文件写入、信息泄露、CRLF、LDAP、XPath、开放重定向、请求走私、条件竞争、CORS、CSRF、弱加密、GraphQL）和 3 个新语言（Ruby、C#、Shell），筛选下拉同步

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
