# AWDP 深度审计引擎回归语料

改 `frontend/dist/assets_v2/lp-ext/awdpplus.js` 之前/之后都跑一遍，防止「修一个漏报换来三个误报」。

## 用法

不需要浏览器，Node 直接跑：

```bash
cd tests/awdp-corpus
node run.js            # 只打汇总，退出码 0=全绿 / 1=有回归
node run.js -v         # 逐文件看命中 / 漏报 / 误报
node run.js --json     # 机器可读
```

默认引擎是 `../../frontend/dist/assets_v2/lp-ext/awdpplus.js`。想对比别的版本：

```bash
LP_FILE=/path/to/other/awdpplus.js node run.js
```

## 语料

| 目录 | 内容 | 期望 |
|---|---|---|
| `corpus/vuln/` | 34 个真漏洞（PHP/Python/Node/Java/Go/Ruby） | 全部命中 |
| `corpus/safe/` | 27 个安全写法（参数化查询、argv 数组、白名单查表等） | 零误报 |
| `corpus/adversarial/` | 15 个专打引擎启发式的对抗样本（净化诱饵、sh -c 包装、pickle、Go 穿越等） | 14/15 命中高危，`x08` 为已知盲区 |
| `corpus/regress/` | 12 个回归样本（净化规则不能误杀 + 屏蔽层不能抹多） | 全部命中 |
| `corpus/modern/` | 17 个新型漏洞样本（Fastjson / Jackson / SnakeYAML / XStream / Newtonsoft / JWT none / NoSQL / zip-slip / Spring4Shell / MyBatis 等） | 全部命中 |
| `corpus/blind/` | 已知盲区，不计分 | 见其 README |

## 当前基线

```
真漏洞     34/34 = 100.0%
安全代码   27/27 = 100.0%
回归       12/12 = 100.0%
新型漏洞   17/17 = 100.0%
对抗语料   14/15 =  93.3%
```

`corpus/adversarial/x08_js_proto_direct.js` 是已知盲区：
`target[k] = src[k]` 与 `arr[i] = x` 在无类型信息时不可区分，
只报低置信「深合并可能污染原型链」，不升级为高危。

## 屏蔽层审计（`oracle/mask-audit.js`）

`run.js` 只能回答「这条样本报没报出来」，回答不了「为什么没报出来」。
引擎是**先屏蔽注释/字符串、再找 sink** 的两段式，第一段抹多了就必然漏报，
而 `node --check` 查不出这种错（引擎不报语法错，它只是少看几行）。

`oracle/mask-audit.js` 专测第一段：屏蔽后**再编译一遍**，编译不过就是抹多了。

```bash
node oracle/mask-audit.js <目录或文件> [-v] [--json] [--cap N] [--no-compile]

node oracle/mask-audit.js /usr/local/lib/node_modules        # JS
node oracle/mask-audit.js /opt/homebrew/Cellar/php/8.5.12_1  # PHP
```

三道检查：行数守恒 / 屏蔽后能编译 / 整行被抹清单。
单行 >2000 字符的压缩代码里 `/` 不可判定，编译失败单独归为 `minified` 不计分。

v1.3.1 的 5 个漏报 bug 全部由它抓出（Python `//`、JS 正则字面量、JS 嵌套模板、
PHP shebang、PHP heredoc），见 `CHANGELOG.md`。

## 另附真实世界压测

1200 个第三方 Python 库文件：告警 178 个文件（14.8%），HIGH 14 / CRITICAL 2。
其中 CRITICAL 均为 IPython 调试器里的真实 `exec(code, ...)` 与 `subprocess.Popen(cmd, shell=shell)`。
HIGH 里主要是 CLI 工具把 `sys.argv` 当路径用（IPython/PIL 这类本身就是命令行程序，
按规则算「路径可控」，属于已知口径放宽，不是引擎错误）。
