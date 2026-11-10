# 24 · 命令行版代码审计（awdp-audit CLI）

> 网页端「🔬 深度审计」要开浏览器、要 12801 扩展服务在跑、一次只能挑一个包上传。
> 比赛现场想批量扫、想在 CI 里卡住、想 `grep` 一下历史报告 —— 都不方便。
> 所以抽了个命令行版：**同一套引擎，同一个 `awdpplus.js`，规则零漂移**，`node` 一行就能扫。

- 位置：`cli/awdp-audit.js`（主程序）+ `cli/awdp-audit`（macOS/Linux 启动器）+ `cli/awdp-audit.cmd`（Windows 启动器）
- 引擎：运行时从 `frontend/dist/assets_v2/lp-ext/awdpplus.js` 里切出分析段，**不复制、不重写**
- 依赖：**只有 Node.js ≥ 18**，不需要 `npm install`，不需要 Python
- 规则：331 条（污点来源 66 / 危险函数 212 / 静态特征 53），26 类漏洞，8 种语言

---

## 一、环境要求

| 项目 | 要求 | 说明 |
|---|---|---|
| Node.js | **≥ 18** | ZIP 解包用 `DecompressionStream('deflate-raw')`，Node 16 没有 |
| 中文编码 | 无额外要求 | Node ≥ 14 自带 full-ICU，`decodeText` 能解 GBK 源码 |
| 第三方包 | **0 个** | 纯标准库（`fs` / `path` / `zlib` 都不需要手动引入） |

```bash
node -v          # v24.21.0 之类，≥ v18.0.0 即可
```

> 低于 18 也能扫**目录和单文件**，只是 `.zip` 输入会报错 —— 手动解压再传目录即可。

---

## 二、三种启动方式

```bash
# ① 直接用启动器（已 chmod +x，在包根目录下）
./cli/awdp-audit ./src

# ② 用 node 显式调用（跨平台通用）
node cli/awdp-audit.js ./src

# ③ Windows CMD / PowerShell
cli\awdp-audit.cmd .\src
```

启动器只做一件事：把参数原样转给 `awdp-audit.js`，所以三种方式行为完全一致。
想全局可用，加个别名即可：

```bash
# ~/.zshrc
alias awdp-audit='/path/to/LingOps_v0.2_darwin_arm64/cli/awdp-audit'
```

---

## 三、输入：目录、单文件、ZIP

```bash
awdp-audit ./app                      # 整个目录，递归
awdp-audit ./app/admin.php            # 单个文件
awdp-audit challenge.zip              # 比赛发的源码包，直接扔进去
awdp-audit ./app ./lib ./extra.zip    # 多个目标混着给
```

扫描范围规则（和网页端一致）：

- **跳过**：`vendor/`、`node_modules/`、`dist/`、`build/`、`target/`、`.git/`、`test(s)/` 等第三方/构建目录（`--vendor` 可关掉）
- **跳过**：二进制文件（含 `\0`）、单文件 > 3MB、`.png/.jpg/.zip/.so/.exe` 等非源码后缀
- **认的语言**：PHP / Java(JSP) / Go / Python / Node.js / Ruby / ASP(ASPX) / C#，其余后缀不扫
- ZIP 内的目录层级保留，报告里的 `file` 字段就是包内相对路径

> ZIP 只解内存，**不会落盘**，也不会有路径穿越（引擎自带 `readZip` 已做过滤）。

---

## 四、看懂输出

### 4.1 默认文本格式

```bash
awdp-audit tests/awdp-corpus/corpus/vuln -s critical
```

```
awdp-audit v1.3.9 · 跨行污点分析引擎
  34 个文件（PHP×10 Python×8 Node.js×7 Java/JSP×3 Go×3 Ruby×3），跳过 0 个

  CRITICAL a01_php_sqli.php:4                       sqli
           SQL 执行
           │ $r = mysqli_query($conn, $q);
           └ 污点来源 L2 $_GET/$_POST 数组取值 · $id = $_GET['id'];
  CRITICAL a02_php_rce.php:3                        rce
           命令执行函数
           │ system("ping -c 1 " . $host);
           └ 污点来源 L2 $_GET/$_POST 数组取值 · $host = $_GET['host'];

  ────────────────────────────────────────────────────────
  严重 5  ·  高危 0  ·  中危 0  ·  低危 0   合计 5 处 / 34 文件 / 20ms
```

每一条读法：

| 行 | 含义 |
|---|---|
| `CRITICAL file:4  sqli` | 严重度 / 文件:行号 / 漏洞类别 |
| `SQL 执行` | 命中的危险函数名 |
| `│ 源码行` | 出问题的那一行原文 |
| `└ 污点来源 L2 ...` | **这个变量从哪来** —— 追到的 source 行，`L2` 是行号 |

「污点来源」是这个引擎和普通正则扫描最大的区别：它告诉你 `$q` 是在第 2 行由 `$_GET['id']` 拼出来的，
所以第 4 行那句 `mysqli_query` 是真注入，而不是「有个变量进去了」。

### 4.2 JSON 格式（给脚本吃）

```bash
awdp-audit ./app -f json -o report.json
```

```json
{
  "tool": "awdp-audit",
  "version": "1.3.9",
  "engine": "frontend/dist/assets_v2/lp-ext/awdpplus.js",
  "targets": ["./app"],
  "files": 34,
  "skipped": 0,
  "langStr": "PHP×10 Python×8 Node.js×7 Java/JSP×3 Go×3 Ruby×3",
  "elapsed_ms": 20,
  "summary": { "critical": 5, "high": 10, "medium": 2, "low": 19, "total": 36 },
  "findings": [
    {
      "file": "a01_php_sqli.php",
      "lang": "php",
      "line": 4,
      "cat": "sqli",
      "sev": "critical",
      "name": "SQL 执行",
      "fix": "改用预处理语句 / 参数化查询",
      "sanitized": false,
      "source": {
        "line": 2,
        "label": "$_GET/$_POST 数组取值",
        "varName": "$id",
        "code": "$id = $_GET['id'];"
      },
      "code": "$r = mysqli_query($conn, $q);",
      "rule": "awdpplus"
    }
  ]
}
```

`rule` 三种取值，决定了这条结果的可信度：

| `rule` | 含义 | 建议 |
|---|---|---|
| `awdpplus` | 污点链路完整（source → sink） | 直接看，基本都是真漏洞 |
| `awdpplus-static` | 静态特征命中（如 `eval(`、`assert(`、弱哈希） | 大概率真，需人工确认上下文 |
| `awdpplus-lowconf` | 危险函数命中但**没追到污点来源** | 默认也输出，`--no-lowconf` 可关 |

`source: null` 就说明没追到来源（低置信），`sanitized: true` 说明中间过了过滤函数（降级但保留提示）。

### 4.3 只看汇总

```bash
$ awdp-audit tests/awdp-corpus/corpus/vuln -q
awdp-audit: 34 文件 · 严重 5 高危 10 中危 2 低危 19 · 26ms
```

适合塞进循环里扫一批包。配合 `-f json -o report.json` 可以「屏幕上一行 + 文件里全量」。

---

## 五、选项全表

| 选项 | 取值 | 默认 | 说明 |
|---|---|---|---|
| `-f, --format` | `text` \| `json` | `text` | 输出格式 |
| `-s, --min-sev` | `critical` \| `high` \| `medium` \| `low` | `low` | 只显示不低于该级别 |
| `-c, --cat` | 类别名，逗号分隔 | 全部 | 如 `rce,sqli,upload`，见 4.1 的类别表 |
| `-l, --lang` | `php` \| `java` \| `go` \| `python` \| `node` \| `ruby` \| `asp` \| `csharp` | 全部 | 只扫指定语言 |
| `--exclude` | glob | 无 | 排除路径，**可重复**，如 `--exclude 'tests/*'` |
| `--vendor` | — | 关闭 | 不跳过 `vendor/` `node_modules/` 等 |
| `--no-lowconf` | — | 关闭 | 不输出 `awdpplus-lowconf` 低置信结果 |
| `--fail-on` | `critical` \| `high` \| `medium` \| `low` \| `none` | `high` | 达到该级别时退出码 1 |
| `--engine` | 文件路径 | 自动找 | 指定 `awdpplus.js` |
| `--list-rules` | — | — | 打印规则统计后退出 |
| `-o, --out` | 文件路径 | 无 | 结果同时写文件（与 stdout 内容一致） |
| `-q, --quiet` | — | 关闭 | 只输出一行汇总（`-f json` 时以 JSON 为准） |
| `--no-color` | — | 关闭 | 关 ANSI 颜色（重定向到文件时自动关） |
| `-v, --version` | — | — | 版本 |
| `-h, --help` | — | — | 帮助 |

`--exclude` 是 glob，不是正则：`*` 匹配任意字符（含 `/`），`**` 也是，`?` 匹配单字符。

```bash
awdp-audit . --exclude 'vendor/*' --exclude 'tests/*' --exclude '*.min.js'
```

---

## 六、退出码与 CI 集成

| 退出码 | 含义 |
|---|---|
| `0` | 没有达到 `--fail-on` 级别的问题（也可能是没扫到文件） |
| `1` | 有达到级别的问题 |
| `2` | 参数错误 / 路径不存在 / 引擎加载失败 |

### GitHub Actions

```yaml
name: awdp-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - name: 深度审计
        run: node cli/awdp-audit.js . -s high --fail-on high -f json -o awdp-report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: awdp-report, path: awdp-report.json }
```

### pre-commit（只卡高危）

```bash
#!/bin/sh
# .git/hooks/pre-commit
node cli/awdp-audit.js . -s high --fail-on high -q || {
  echo "发现高危及以上问题，提交已阻止。完整报告：node cli/awdp-audit.js . -s high"
  exit 1
}
```

### 只想看不想卡

```bash
awdp-audit . --fail-on none    # 永远退出 0
```

---

## 七、规则集：`--list-rules`

```bash
$ awdp-audit --list-rules

规则统计（引擎 v1.3.9）

  语言        污点来源   危险函数   静态特征
  PHP         11        42        43
  Java/JSP    13        33        48
  Go          11        21        43
  Python      7         35        44
  Node.js     14        33        46
  Ruby        4         17        44
  ASP/ASPX    3         12        43
  C#          3         19        45
  ────────────────────────────────────────────
  合计          66        212       53     = 331 条

  注：静态特征多为多语言共用，按语言分列之和会大于总数。
  漏洞类别 26 类
```

**331 = 66 污点来源 + 212 危险函数 + 53 静态特征**，和网页端「深度审计」面板显示的数字完全一致
（因为就是同一份数据）。

---

## 八、和网页端是什么关系

一句话：**同一个引擎，两套壳。**

```
frontend/dist/assets_v2/lp-ext/awdpplus.js     ← 唯一事实来源（2078 行）
        │
        ├── 浏览器：注入到 LingOps 页面，画 UI、调扩展后端做 AI 修复包
        └── 命令行：切出「分析段」（第 1 行 ~ "8. 与官方引擎对比" 之前），在 Node 里跑
```

- **规则零漂移**：改 `awdpplus.js` 的规则，网页端和 CLI 同时生效，不需要同步第二份
- **不依赖扩展服务**：12801 不用起，也不需要 12800
- **不需要浏览器**：没有 DOM、没有注入、没有缓存问题

引擎边界用两个标记定位（章节标题 `* 8. 与官方引擎对比`，失败则退回 `function getToken(`），
两个都找不到会直接报错 `无法定位引擎边界`，而不是静默扫出空结果。

> 所以**升级 LingOps 官方版本后**，只要 `awdpplus.js` 的整体结构没被重写，CLI 自动跟着新规则走。
> 万一报「无法定位引擎边界」，说明上游把这一段重构了，改 `cli/awdp-audit.js` 里 `loadEngine()` 的
> 两个 marker 即可（各一行）。

### 功能对照

| 能力 | 网页端 | CLI |
|---|---|---|
| 跨行污点分析 | ✅ | ✅ 同一份代码 |
| 26 类漏洞 / 331 条规则 | ✅ | ✅ |
| 多文件、ZIP 上传 | ✅ | ✅ |
| `lingops:ignore` 忽略 | ✅ | ✅ |
| 官方引擎对比（漏报对比） | ✅ | ❌ 需要网页端交互 |
| AI 修复包（`bundle.md`） | ✅ | ❌ 走网页端 21 章 |
| 批量 / CI / 管道 | ❌ | ✅ |
| 不开浏览器 | ❌ | ✅ |

---

## 九、误报怎么处理

和网页端同一套标记，在命中行（或上一行）加注释即可：

```php
// lingops:ignore 爬虫必须请求外部 URL
$html = file_get_contents($target);
```

```java
// lingops:ignore 路径来自白名单常量
new FileInputStream(path);
```

支持 `//`、`#`、`/* */`、`<!-- -->`。被忽略的条数会算在汇总里，不会静默吞掉。

工具本身就要读任意路径 / 出网的（爬虫、指纹识别、SSRF 测试器）属于正常情况，加标记别改代码。

---

## 十、自己验证引擎

CLI 和网页端共用引擎，所以引擎的回归结论对 CLI 同样成立。
用包里自带的 105 个已知答案样本跑一遍：

```bash
node tests/awdp-corpus/run.js          # 退出码 0 = 全绿
node tests/awdp-corpus/run.js -v       # 看每个样本
```

也可以直接拿 CLI 扫：

```bash
node cli/awdp-audit.js tests/awdp-corpus/corpus/vuln -q   # 应 34/34 命中
node cli/awdp-audit.js tests/awdp-corpus/corpus/safe -q   # 应 0 处问题
```

v1.3.9 实测（CLI 与 `run.js` 结论一致）：

| 语料 | 文件数 | 期望 | CLI 结果 |
|---|---|---|---|
| `corpus/vuln` | 34 | 全命中 | **34 / 34** ✅ |
| `corpus/safe` | 27 | 零误报 | **0 处** ✅ |
| `corpus/regress` | 12 | 全命中 | **12 / 12** ✅ |
| `corpus/modern` | 17 | 全命中 | **17 / 17** ✅ |
| `corpus/adversarial` | 15 | 高危以上 | **14 / 15**（已知盲区 `x08_js_proto_direct.js`） |

---

## 十一、性能

| 场景 | 耗时 |
|---|---|
| 34 个文件的语料目录 | ~20ms |
| 整个仓库 130 个文件 | ~220ms |

纯 CPU、单线程、无网络。几千个文件也是秒级，不用并发。

---

## 十二、限制

1. **只做静态分析**，不跑代码、不连数据库，所以「运行期才拼出来的 SQL」追不到
2. **不做跨文件数据流**：变量从 A 文件传到 B 文件就断了（网页端也一样）
3. **不认自定义框架的封装**：自己写的 `db()->query()` 若不在危险函数表里就不报 —— 可以手动加进 `awdpplus.js` 的 `SINKS`
4. **ZIP 需要 Node ≥ 18**；老环境先解压
5. **`x08_js_proto_direct.js` 这类原型链直写是已知盲区**，靠人工补
6. 扫描结果**不等于**能利用：报的是「污点能流到危险函数」，实际能不能打穿还要看过滤和上下文

---

## 十三、一分钟速查

```bash
# 比赛拿到源码包，先看有没有严重洞
awdp-audit challenge.zip -s critical

# 只看能拿 shell 的
awdp-audit ./src -c rce,upload,lfi,deserialization

# 出报告给队友
awdp-audit ./src -f json -o report.json

# 修完复查，只看高危以上
awdp-audit ./src -s high -q

# 卡 CI
awdp-audit . -s high --fail-on high -q
```

---

**相关章节**：[20 深度审计](20-awdp-deep-scan.md)（网页端用法与原理）、[21 AI 修复包](21-ai-fix-bundle.md)、
[12 AWDP Fix](12-awdp-fix.md)（补丁流程）、[16 速查表](16-cheatsheet.md)
