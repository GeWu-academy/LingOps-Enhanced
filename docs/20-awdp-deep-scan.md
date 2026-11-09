# 20 AWDP 深度审计（跨行污点分析扩展）

> 扩展模块 · 纯前端注入 · 不需要额外后端服务
> 入口：`/awdp/break` 或 `/awdp/fix` 页面 →「上传文件 / ZIP」旁边的 **🔬 深度审计** 按钮

---

## 一、为什么官方扫描「识别不到很多漏洞」

官方的 AWDP Break / Fix 扫描引擎不是「纯正则扫描器」，而是 **污点门控 + 正则** 的两级结构：

```
第一级：找 source（$_GET / getParameter / r.URL.Query() / request.args ...）
        ↓ 只有「含 source 的行」和「引用了被污染变量的行」才会进入第二级
第二级：在这些行上跑正则规则（system( / exec( / unserialize( ...）
```

这个设计能有效压噪声，但也带来了三个结构性漏报。以下都是在本机 74 个漏洞样本上实测得到的结论。

### 漏报原因 1：纯字面量 sink 行根本不扫

```php
myCustomFunc($a);          // $a = $_GET['a'];  ✅ 命中（行内有污点变量）
myCustomFunc2("literal");  // ❌ 不命中（没有污点，规则压根不执行）
system("ls -la");          // ❌ 不命中（同上，即使这是明摆着的命令执行）
```

**结论：凡是「sink 的参数里没有污点变量」的写法，官方引擎一律不报。** 半混淆、间接封装、常量拼接的代码因此全部漏掉。

### 漏报原因 2：不传播二级变量

```php
$f = $_GET['f'];      // 一级：被污染
$g = $f;              // 二级：官方引擎不传播
exec("cmd " . $g);    // ❌ 漏报
```

同样地 `String c = req.getParameter("c"); String d = c;` 之后的 `Runtime.exec(d)` 也漏报。

### 漏报原因 3：Go 语义引擎只覆盖文件操作

官方对 Go 有一套 AST 语义引擎，但只识别 `os.Open / os.ReadFile / ioutil.*` 等**文件操作**，不识别 `exec.Command`。所以 Go 的命令执行、SQL 拼接、模板注入基本全漏。

实测（同一份 74 文件语料，官方 335 条规则）：

| 文件 | 漏洞 | 官方 | 深度审计 |
|---|---|---|---|
| `go/cmd.go` | `exec.Command("sh","-c",c)` | ❌ | ✅ critical |
| `java/Deser.java` | `ObjectInputStream.readObject()` | ❌ | ✅ critical |
| `php/ldap.php` | `ldap_search($dn, ...)` | ❌ | ✅ high |

官方：扫描 74 个文件，130 条 findings，命中 71 个文件
深度审计：命中 74 个文件，105 条 findings（去噪后，v1.2.0 引擎）

> 注意：官方「命中文件数」并不低，说明它规则不少；漏的是**具体漏洞类型**（Go RCE、Java 反序列化、LDAP 注入、跨行/二级变量链路）。所以正确用法是**两个都跑**，不是二选一。

### 补规则也救不回来

一开始的思路是「加规则」：导入 150 条自定义规则（规则总数 335）后重扫，`go/cmd.go`、`java/Deser.java`、`php/ldap.php` 依然 0 命中——因为**门控在第一级就把这些行滤掉了，规则再多也轮不到执行**。

这就是本扩展存在的原因：**绕开门控，自己做跨行污点分析**。

---

## 二、深度审计是怎么做的

四遍扫描，全部在前端 JS 里完成（文件不落盘、不出本机）：

### 第 1 遍：标记 source

每个语言一张 `SOURCES` 表，命中即把该行标记为污点源，并污染：

- 该行**所有**标识符（宽松：`$_GET['a']` 所在行里的变量都可能被污染）
- 该行的**赋值目标**（`$id = $_GET['id'];` → `$id` 污染，来源行 = 当前行）

PHP 特别处理：**只认 `$` 开头的标识符**。这样 `$sql = "SELECT * FROM t WHERE id = $id";` 里的字符串插值 `$id` 也能参与传播（其他语言先抹掉字符串字面量，避免把 `"bypass"` 这种英文单词当变量）。

### 第 2 遍：迭代传播（最多 8 轮直到收敛）

```
行内出现被污染标识符  →  该行的赋值目标继承污点
行内有函数调用并赋值  →  返回值变量继承污点（var x = foo(tainted)）
```

这解决了「二级/三级变量」漏报：`$f → $g → exec(...)`、`c → d → Runtime.exec(d)`。

### 第 3 遍：sink 匹配（只认参数区）

每个语言一张 `SINKS` 表（约 100 条），匹配后**只提取 sink 的参数区**（支持跨行括号平衡，最多 8 层），参数区里必须存在被污染变量才报。

- 这样 `echo 'bypass'` 不会因为「整行有污点」而误报；
- 参数区完全没有标识符（如 `include` 后换行）才退回整行判定；
- sink 只在**代码区**匹配（字符串字面量内容被抹成空格），避免把注释/字符串里的 `system(` 当漏洞。

### 第 4 遍：静态弱点

与污点无关的固定模式：硬编码密钥、`debug=True`、`display_errors=On`、`allow_url_include`、弱哈希、弱随机数、`0777` 权限、CORS `*`、type juggling、`isset($_GET[...])` 直接提权、SQL 字符串拼接等。

### 净化识别

`sanitizedFor()` 会检查 sink 参数区（及其来源行）是否出现 `escapeshellarg / intval / basename / htmlspecialchars / realpath / prepared statement / filepath.Base ...`。命中则不报，或降级为 `low` 并标注「已净化」（UI 里默认隐藏，可用「显示已净化」开关查看）。

---

## 三、使用

1. 打开 `/awdp/fix`（或 `/awdp/break`）；
2. 点「上传文件 / ZIP」右侧的 **🔬 深度审计**；
3. 把源码 **ZIP 拖进面板**，或点「选择文件 / ZIP」、也可以「选择文件夹」（Chromium 系浏览器支持）；
4. 自动出结果：

```
文件 74   命中文件 74   问题总数 105   严重 30   高危 34   中危 30   低危 11
耗时 8ms   语言分布 Go×4 · Python×14 · Java/JSP×7 · PHP×39 · Node.js×10
```

5. 顶部可按 **等级 / 类型 / 关键词** 过滤，可切换「显示已净化」「跳过依赖目录（node_modules、vendor、.git…）」「低置信兜底」；
6. 点 **对比官方引擎** → 会把同一个 ZIP 传给官方 `POST /api/v1/awdp/scan-upload`，等扫描完成后列出「官方漏报的文件」，用来验证到底谁漏了什么：

```
官方引擎：扫描 74/74 文件，规则 102 条，产出 130 条 findings，命中 71 个文件
深度审计：命中 74 个文件
官方漏报的 3 个文件：php/ldap.php  java/Deser.java  go/cmd.go
```

7. **导出 JSON / 导出 Markdown**：JSON 可二次处理，Markdown 直接贴到 AWDP 报告/工单里。

### 结果字段

每条 finding 都带完整的**污点链路**，修复时不用再猜数据从哪来：

```
critical | php/cmd.php:4 | rce | 命令执行函数
         | L3 $_GET/$_POST 数组取值 -> $ip
         | 修复：改用白名单 + escapeshellarg()
```

`source.line` / `source.varName` / `source.code` 就是污点来源行、变量名和原始代码。

---

## 四、支持的漏洞类型

| 类别 | 例子 |
|---|---|
| `rce` | `system/exec/shell_exec/passthru/popen/proc_open`、反引号、`eval`、`assert`、`create_function`、`preg_replace /e`、`call_user_func`、**变量函数 `$a($c)`**、`Runtime.exec`、`ProcessBuilder`、`exec.Command`、`os.system`、`subprocess`、`shell=True` |
| `sqli` | `mysqli_query`、`->query/exec/prepare`、`createStatement/executeQuery`、`.Query/.Exec`、`cursor.execute`、SQL 字符串拼接（含未执行的赋值） |
| `deserialization` | `unserialize`、phar、`ObjectInputStream`、`XMLDecoder`、`pickle`、`yaml.load`、`gob` |
| `lfi` / `path` | `include/require`、`fopen/readfile/unlink/file_get_contents`、`new File*`、`os.Open`、`open()`、`send_file` |
| `ssti` | `Twig/Blade`、`SpelExpressionParser/Ognl/MVEL`、`template.New/Must`、`render_template_string`、**ThinkPHP `->fetch()`** |
| `ssrf` | `curl_setopt(CURLOPT_URL)`、`fsockopen`、`new URL`、`http.Get`、`requests.*`、`axios` |
| `upload` | `move_uploaded_file`、`FileItem.write`、`transferTo`、`save()` |
| `xxe` | `simplexml_load_string`、`DocumentBuilderFactory`、`resolve_entities=True`、**`etree.fromstring`** |
| `ldap` | `ldap_search/ldap_bind`、`InitialDirContext.search` |
| `auth` / `crypto` / `config` / `secret` / `xss` / `header` / `redirect` / `cors` / `random` | 会话固定、type juggling、ECB、弱哈希、弱随机、调试开启、硬编码密钥、未转义输出、CRLF、开放重定向、CORS `*` |

语言：PHP、Java/JSP、Go、Python、Node.js/JS、Ruby、ASP/ASPX、C#。

---

## 五、和官方扫描怎么配合

| 场景 | 用哪个 |
|---|---|
| 比赛要交「官方格式」的漏洞报告 / 补丁包 | 官方 Fix 扫描（产出 patch 包） |
| 官方扫完觉得「我这还有洞没报」 | 深度审计 + **对比官方引擎** 找出漏报文件 |
| 要看清一条漏洞的完整数据流 | 深度审计（带 source 行 + 变量名） |
| 需要 Go / Java 反序列化 / LDAP / ThinkPHP 这类官方弱项 | 深度审计 |
| 批量出报告给队友 | 导出 Markdown |

**推荐流程**：先跑官方（拿官方结论）→ 再跑深度审计 → 点「对比官方引擎」→ 把官方漏报的文件按严重级别挨个人工确认 → 用深度审计的 source 链路写补丁。

---

## 六、调试与维护

浏览器控制台里：

```js
window.__lpAwdpPlusApi.version              // 扩展版本
window.__lpAwdpPlusApi.state                // { files, findings, compare, ... }
window.__lpAwdpPlusApi.analyzeText(code, 'php', 'x.php')   // 直接分析一段代码
window.__lpAwdpPlusApi.analyzeFile('a.php', code)          // 分析一个文件
window.__lpAwdpPlusApi.open()               // 打开面板
```

加规则：编辑 `frontend/dist/assets_v2/lp-ext/awdpplus.js` 里的 `SOURCES` / `SINKS` / `SANITIZERS` / `PATTERNS` 四张表。`SINKS` 每项：

```js
{ re: /正则/g, cat: 'rce', sev: 'critical', name: '显示名', fix: '修复建议', raw: false }
```

- `raw: true` 表示正则要在**原始行**上匹配（需要看字符串内容的规则，例如 `preg_replace('/e')`）；
- 默认在「抹掉字符串字面量」的代码区匹配，避免注释/字符串误报。

改完必须**同时**改两处版本号，否则浏览器用缓存：

1. `frontend/dist/index.html`：`boot.js?v=N` → `N+1`
2. `frontend/dist/assets_v2/lp-ext/boot.js`：`awdpplus.js?v=M` → `M+1`

然后 `Cmd+Shift+R` 强刷。

> 官方升级覆盖前端后，`index.html` 和 `boot.js` 会被替换，扩展注入需要重做一遍（与第 17/18/19 章的扩展同理）。`awdpplus.js` 本体不受影响。

---

## 七、已知边界

1. **不做跨函数分析**：`getUserInput()` 内部读 `$_GET`、外层 `exec($x)` 的写法，除非同一行/同一文件内有赋值链，否则不追。
2. **不做别名分析**：`$a = &$b`、`$GLOBALS['x']` 这类引用赋值只做同名匹配。
3. **动态包含/动态类名**（`include $dir . $file` 的二次拼接、`new $class()`）只能报到「变量可控」为止。
4. **PHP 只认 `$` 变量**：`${'a'.'b'}` 这种可变变量名不解析。
5. 「已净化」判定基于关键字白名单，**宁可降级也不误杀**，所以看到 `low / 已净化` 时仍建议人工看一眼。
6. **净化必须真的流到 sink**（v1.3.0 起）：`$p = realpath($f); readfile($f);` 里 `realpath` 的结果没被 `readfile` 使用，
   属于「诱饵」，仍然会报。反过来 `$real = realpath($root . $f); readfile($real);` 才算已净化。
7. **原型污染只做到「低置信」**：`target[k] = src[k]` 与普通数组循环 `arr[i] = x` 在无类型信息时字符串上完全一样，
   强行升级会把所有数组遍历写成高危，所以只报 `low` 并标注「深合并可能污染原型链」，需人工判断。
8. 单文件 > 2 MB 或压缩包 > 50 MB 会被跳过（前端内存保护）。

---

## 八、把结果直接交给 AI 修（AI 修复包）

扫描出问题后，下一步是改代码。点面板顶部的 **🤖 AI 修复包**（或上传 ZIP 时自动生成）：
扩展会把「源码 + 本次问题清单 + 提问模板」落盘到 `~/LingOps-AWDP/<id>/`，
并给出 `http://127.0.0.1:12801/awdp/<id>/` 链接，直接丢给本地 AI 或复制给在线 AI 即可。
详见 [21 AI 修复包](21-ai-fix-bundle.md)。

---

## 九、v1.2.0 修复的漏报（如果你之前觉得「根本审不出漏洞」，看这一节）

v1.1.0 有几处会**静默吞掉整条链**，表现就是「拖进去 0 条」或「只报几条无关紧要的」：

| # | 问题 | 影响 | 修法 |
|---|---|---|---|
| 1 | `SOURCES.node` 只认 `req.query / req.body / ctx.query` | Next.js / Web Fetch API / Fastify / NestJS 全部 0 条 | 补 `request.formData()/json()/text()/arrayBuffer()`、`new URL().searchParams`、`context.params`、`request.body`、`@Query()/@Param()/@Body()`、`getServerSideProps` |
| 2 | `SANITIZERS.xxe` 把 `LIBXML_NOENT` 当「净化函数」 | PHP XXE 被判定为已净化 → 直接丢弃，**永远看不到** | 移除；`LIBXML_NOENT` / `LIBXML_DTDLOAD` 本身就是漏洞开关，改为新增静态规则直接报 |
| 3 | 字符串内容被整段抹掉（`codeOnly`） | Ruby `system("ls #{x}")`、PHP `"... WHERE id=$id"`、Python `f"{x}"`、C# `$"{x}"` 里的变量全丢 → 漏报 | 只抹内容，**保留插值表达式** |
| 4 | 参数区有标识符但没污点 → `continue` 静默丢弃 | 跨文件 / 框架注入的数据流全丢 | 新增「低置信兜底」：高风险 sink（rce/sqli/xxe/ssti/lfi/deserialization）仍以 `low` 级别提示「未追到污点来源」，可在顶部开关关闭 |
| 5 | 无 Node 侧 XXE / 外部解析器规则 | `spawn('xmllint', ['--noent', ...])` 这类真实 RCE 面完全看不到 | 新增 `--noent/--loaddtd`、`libxmljs/xml2js/fast-xml-parser`、`xmllint/xsltproc/convert` 规则 |
| 6 | NestJS 装饰器参数、对象解构赋值未识别 | `@Query('c') c: string`、`const { name } = await request.formData()` 的变量不污染 | `declTargets` 补装饰器参数、`{a, b: c}` 解构、`({ params })` 解构入参 |
| 7 | Ruby `params[:c]` 经变量中转后漏报 | 见 #3 | 同 #3 |

**回归基准**（`source-data/corpus-task-1`，74 文件）：97 → **105** 条，无任何原有 finding 丢失。
真实漏报案例 `gallery_attachment`（Next.js 12 文件）：0 → **3** 条（XXE 高危 + 路径高危 + spawn 低置信）。

**已知取舍**：低置信兜底会把「看起来危险但确实安全」的调用也列出来（`low` 级、明确标注「未追到污点来源」）。
嫌吵就取消勾选「低置信兜底」，引擎行为与 v1.1.0 的严格污点模式一致。

---

## 十、误报怎么处理（`lingops:ignore`）

引擎是启发式的，总会有「看着像漏洞其实不是」的情况。比如工具本身就要出网（爬虫、指纹识别），
或者路径后缀是写死的（`dir + "/*.js"`）。这种**别改代码去迎合扫描器**，加一行标记即可：

```php
$dir = safe_outdir($argv[1]);   // lingops:ignore 路径来自 CLI 参数，已用 safe_outdir 归一化
scan_dir($dir);
```

```python
resp = requests.get(target)     # lingops:ignore 爬虫职责就是访问目标站
```

规则：

| 写法 | 作用范围 |
|---|---|
| 命中行带标记 | 只忽略这一条 |
| 命中行的**上一行**带标记 | 忽略下一行（给不方便改行的语言留口） |
| `lingops:ignore` / `lingops:safe` / `nosec` | 三个词等价，随便用哪个 |

被忽略的条数会显示在扫描汇总里（「已忽略 N 条」），不会静默吞掉 —— 免得你以后忘了自己屏蔽过什么。

**什么时候不该用**：只要能改代码就改代码。`lingops:ignore` 是给「业务上必须这么写」的场景用的，
不是给「懒得修」用的。

---

## 十一、自己验证引擎（回归自测）

引擎自带 88 个已知答案的样本（真漏洞 34 / 安全写法 27 / 回归 12 / 对抗 15），
装在 `tests/awdp-corpus/`，**不需要浏览器**，Node 直接跑：

```bash
cd tests/awdp-corpus
node run.js          # 只打汇总
node run.js -v       # 逐文件看命中/漏报/误报
```

当前基线：

```
  真漏洞   34/34  100.0%  ✅
  安全代码   27/27  100.0%  ✅
  回归   12/12  100.0%  ✅
  对抗语料   14/15   93.3%  ✅  （另有 1 个已知盲区不计分）
```

退出码 0 = 全部通过，1 = 有回归 —— 可以挂到 `git commit` 钩子或 CI 上。

**改过引擎一定要跑这个**。最容易踩的坑：在 JS 正则里写 Python 风格的字符类、
`REGEXP.test()` 带 `g` 标志有 `lastIndex` 状态、字符串里的引号把正则截断 —— 这些
`node --check` 全都查不出来，只有跑语料才会炸。

换一个引擎版本对比：

```bash
LP_FILE=/path/to/other/awdpplus.js node run.js
```

### 屏蔽层单独测（`oracle/mask-audit.js`）

深度审计分两步：**先把注释和字符串抹掉，再在剩下的代码里找 sink**。
第一步抹多了，第二步就什么都找不到 —— 这是「扫不出漏洞」最常见的原因，而且
`node --check` 查不出来（引擎自己不报语法错，它只是少看了几行）。

`tests/awdp-corpus/oracle/mask-audit.js` 专门查这件事：把每个文件屏蔽一遍，
**再拿编译器验一遍**。

```bash
node tests/awdp-corpus/oracle/mask-audit.js <目录或文件> [-v] [--json] [--cap N] [--no-compile]

# 例：拿系统里的真实代码压测
node tests/awdp-corpus/oracle/mask-audit.js /usr/local/lib/node_modules
node tests/awdp-corpus/oracle/mask-audit.js /opt/homebrew/Cellar/php/8.5.12_1
```

三道检查：

| 检查 | 含义 | 不过说明什么 |
|---|---|---|
| 行数守恒 | 屏蔽前后行号必须一一对应 | 报出来的行号全错，去 IDE 找不到 |
| 屏蔽后能编译 | `py_compile` / `node --check` / `php -l` | 抹多了，真实代码被吃掉 |
| 整行被抹 | 列出被整行抹空的行 | 人工确认那些确实是注释 |

单行超过 2000 字符的文件（压缩/混淆代码）里 `/` 是除号还是正则**不可判定**，
这类文件编译失败单独归为 `minified`，不计入结构性问题。

v1.3.1 就是靠它抓出 5 个漏报 bug（Python `//`、JS 正则字面量、JS 嵌套模板、
PHP shebang、PHP heredoc），详见 `CHANGELOG.md`。

**这四套语料能证明什么、不能证明什么**：

- 能证明：改规则没有把已知漏洞漏掉、没有把已知安全写法误杀。
- 不能证明：它对你手上的**真实项目**够用。样本是我按常见漏洞形态写的，
  和你的代码分布不一样。真实项目请自己抽 20 个文件人工核对一遍，再决定信不信结果。
