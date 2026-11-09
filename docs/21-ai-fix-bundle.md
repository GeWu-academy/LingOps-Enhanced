# 21 AI 修复包（上传 ZIP 自动生成本地链接）

> 扩展模块 · 需要扩展后端 `12801`（`start-ext.sh`）
> 入口：AWDP Break / Fix 页上传 ZIP 后**自动弹出**；或「🔬 深度审计」面板里的 **🤖 AI 修复包** 卡片

---

## 一、它解决什么问题

官方 AWDP 扫描只给你一张「问题列表」，不保留源码目录（`data/` 里只有 `lingops.db` 和 `poc/`），
所以你没法把「源码 + 扫描结果」整体丢给 AI 让它改代码 —— 每次都得手动复制粘贴几十个文件。

现在：**上传一次 ZIP，立刻得到一个链接（和磁盘目录）**，把它交给 AI 即可：

| AI 类型 | 怎么用 |
|---|---|
| 本地 AI（Cursor / Claude Desktop / Copilot / 本地模型） | 直接把**磁盘目录**给它：「读 `/Users/你/LingOps-AWDP/<id>/`，按 `prompt.txt` 的要求修漏洞」 |
| 在线 AI（ChatGPT / Claude / DeepSeek / 通义） | 打不开 `127.0.0.1`，用「**复制 AI 提示词**」+「**复制全文源码**」，或下载 `bundle.md` 上传 |
| 命令行 AI（`aider` / `llm` / `ollama`） | `cd ~/LingOps-AWDP/<id>/src` 后在源码目录里跑，`prompt.txt` 作为首条指令 |

---

## 二、生成的产物

```
~/LingOps-AWDP/<id>/            # <id> 形如 20261108-014828-awdp_test.zip
├── src/                        # 解压出来的源码（保留原目录结构）
├── index.html                  # 目录页：问题清单 + 文件树 + 每个文件的可点链接
├── bundle.md                   # 全文包：元信息 + 问题清单 + 全部源码（给 AI 的主文件）
├── bundle.txt                  # 同上，纯文本版（部分在线 AI 对 .md 排版不友好时用）
├── attack-plan.md              # ⚔️ 攻击路线：每条漏洞的入口 / payload / 预期回显 / flag 位置
├── fix-plan.md                 # 🛡️ 修复清单：每条根因 / 最小改动 / 验证方法 + 止血顺序
├── local-ai.md                 # 🤖 给本地 AI 的任务书（整篇复制给它即可）
├── make_patch.py               # 📦 把 fixed/ 里改好的完整文件转成 git apply 能用的补丁
├── check_fixed.py              # ✅ 验收门：补丁生成前先查语法/路径/已知坏写法/覆盖率
├── extract_files.py            # ✂️ 备用：把在线 AI 的聊天回复拆成 fixed/ 里的真实文件
├── prompt.txt                  # 给 AI 的提问模板（可直接粘贴）
├── findings.json               # 结构化问题清单（meta + findings）
├── tree.txt                    # 文件树
└── README.md                   # 等同 prompt.txt
```

对应的链接（`<base>` = `http://127.0.0.1:12801`）：

| 链接 | 说明 |
|---|---|
| `<base>/awdp/<id>/` | 目录页（人看） |
| `<base>/awdp/<id>/bundle.md` | 全文包（AI 看） |
| `<base>/awdp/<id>/attack-plan.md` | ⚔️ 攻击路线（break 场景优先看） |
| `<base>/awdp/<id>/fix-plan.md` | 🛡️ 修复清单（fix 场景优先看） |
| `<base>/awdp/<id>/local-ai.md` | 🤖 本地 AI 任务书（整篇复制给本地 AI） |
| `<base>/awdp/<id>/make_patch.py` | 📦 生成补丁的脚本（下载） |
| `<base>/awdp/<id>/check_fixed.py` | ✅ 验收门脚本（下载） |
| `<base>/awdp/<id>/extract_files.py` | ✂️ 拆在线 AI 回复的脚本（备用） |
| `<base>/awdp/<id>/prompt.txt` | 提问模板 |
| `<base>/awdp/<id>/findings.json` | 结构化结果 |
| `<base>/awdp/<id>/tree.txt` | 文件树 |
| `<base>/awdp/<id>/raw?p=src/相对路径` | 按需读单个源文件 |

`bundle.md` 里已经包含：本次是 break 还是 fix、文件数、各级别问题数、**问题清单（含行号/污点链/修复建议）**、
每条问题的 **⚔️ 攻击思路 / 🛡️ 修复思路**，以及**全部源码**。所以在线 AI 只要拿到这一个文件就能开工，
不需要再逐个问文件。

> **为什么要 attack-plan / fix-plan**
> `bundle.md` 是给 AI 读的「全量上下文」，很长；这两个文件是给人读的「行动清单」，短且按优先级排好：
> - `attack-plan.md`：第一节直接给「最快拿分路径」前 3 条，第二节逐条给 入口 → payload → 看什么回显 → flag 在哪；
> - `fix-plan.md`：第一节给「5 分钟止血清单」（同类漏洞合并成一条），第二节逐条给 根因 → 最小改动 → 验证方法。
>
> 两个文件都可以直接丢给 AI，AI 拿到后不需要自己排序，按清单干活即可。

---

## 三、怎么用（三条路径）

### 1. 官方 Break / Fix 页（最省事）

1. 打开 `/awdp/break` 或 `/awdp/fix`；
2. 照常用官方「上传文件 / ZIP」上传压缩包；
3. 上传完成后右下角自动弹出 **🤖 AI 修复包已生成**，显示文件数 / 问题数 / 链接；
4. 点「复制提示词」→ 粘给 AI；或点「复制目录」→ 交给本地 AI。

> 上传时扩展会**顺带跑一遍本地深度审计**（[20 章](20-awdp-deep-scan.md)），所以修复包里带的是
> 「官方结果 + 深度审计结果」合并后的问题清单，通常比官方多几倍。

### 2. 「🔬 深度审计」面板

面板顶部会直接出现 **🤖 AI 修复包** 卡片，含：

- **本地链接**（点「打开目录页」）
- **磁盘目录**（点「复制路径」）
- **复制 AI 提示词** / **复制全文源码** / `bundle.md` / `bundle.txt` / `prompt.txt` 直链
- **重新生成**（改了扫描结果后可再生成一份）

### 3. 命令行 / 脚本

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"

# 直接传 ZIP（multipart 不方便时用 base64，见下）
B64=$(base64 -i /tmp/app.zip | tr -d '\n')
curl -s -X POST http://127.0.0.1:12801/api/awdp/session \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"app.zip\",\"scan_type\":\"fix\",\"zip\":\"$B64\"}" | python3 -m json.tool

# 查看历史（最近 20 个）
curl -s http://127.0.0.1:12801/api/awdp/sessions | python3 -m json.tool

# 删除某个会话
curl -s -X POST http://127.0.0.1:12801/api/awdp/delete \
  -H 'Content-Type: application/json' -d '{"id":"20261108-014828-awdp_test.zip"}'
```

也可以传 `files`（不上传 ZIP，直接给文本），适合脚本里只送部分文件：

```json
{"name":"partial","scan_type":"break",
 "files":[{"path":"app/x.php","text":"<?php system($_GET['c']);"}],
 "findings":[{"sev":"critical","name":"命令执行","file":"app/x.php","line":1,"fix":"escapeshellarg"}]}
```

---

## 四、让 AI 产出真正能用的 patch（重点）

### 为什么 AI 自己写的 patch 几乎一定用不了

让模型直接输出 unified diff，等于让它**自己数行号**。这一步模型几乎必错，典型翻车：

- 只有 `@@` 两个字符，没有 `@@ -3,7 +3,12 @@` 这种 hunk 头；
- 缺 `--- a/path` / `+++ b/path`；
- 上下文行数量不对、行号偏移；
- 文件结尾没有换行。

结果就是：

```bash
git apply qzone_fixes.patch
# error: No valid patches in input

patch -p1 < qzone_fixes.patch
# Only garbage was found in the patch input
```

### 正确做法：把「算行号」从模型手里拿走

```
模型只做它最擅长的：输出「改好的完整文件」
        ↓
脚本做它最擅长的：算行号 + 生成 diff + git apply 自校验
```

### 三步走

**第 1 步：把 `local-ai.md` 整篇丢给本地 AI**

本地 AI（Cursor / Claude Desktop / Copilot / Ollama / LM Studio）能直接读写文件，所以：

1. 让它读 `~/LingOps-AWDP/<id>/src` 和 `bundle.md` / `fix-plan.md`；
2. 让它把每个**改动过的文件用完整内容**写到 `~/LingOps-AWDP/<id>/fixed/` 下，目录结构与 `src/` 一致：

```
fixed/qzone/deploy/app/controllers/AdminController.php
fixed/qzone/deploy/core/Controller.php
```

**关键：没改的文件不要放进 `fixed/`。** 脚本默认把「`src/` 有、`fixed/` 没有」的文件当作**没改**，
不会误删（要删文件得显式加 `--allow-delete`）。

**第 2 步：先过验收门 `check_fixed.py`**

`make_patch.py` 只保证「补丁能打上去」，不保证「补丁是对的」。所以先跑验收门：

```bash
cd ~/LingOps-AWDP/<id>
python3 check_fixed.py            # 退出码 0 = 可以生成补丁
```

它查 7 项（前 4 项 FAIL 直接拦、后 3 项只 WARN）：

| 检查 | 抓什么 |
|---|---|
| §1 路径 | `fixed/` 空目录（AI 只在聊天里贴代码没写文件）、路径与 `src/` 对不上 |
| §1 语法 | `php -l` / `py_compile` / `node --check` 不通过（AI 手写代码写崩了） |
| §2 换行/规模 | CRLF↔LF 被改、单文件改动 >50%（AI 把整文件重写了一遍） |
| §3 已知坏写法 | `const = getenv()`、`$this->viewData` 幻觉属性、裸 `unserialize()`、`mkdir(realpath(...))`、CORS `*`、`md5($_GET)` |
| §4 覆盖率 | 对照 `findings.json`：critical/high 没改到 = FAIL，medium/low = WARN |

常用参数：`--fixed <dir>` / `--src <dir>` / `--strict`（WARN 也算失败）/ `-v`（打印明细）/ `--max-ratio 0.5`

**第 3 步：生成并自校验补丁**

```bash
cd ~/LingOps-AWDP/<id>

# 只生成补丁（先看 stat）
python3 make_patch.py fixed/

# 生成 + 直接应用到靶场（推荐，层级自动探测）
python3 make_patch.py fixed/ --apply-to /Users/shu/ctf/qingcen/qzone
```

输出：

```
提示：src/ 有 48 个文件、fixed/ 里只有 2 个 —— 未出现的 46 个按「没改」处理，不会被删除。

改动文件 2 个：
  M deploy/app/controllers/AdminController.php                   371 -> 374 行
  M deploy/core/Controller.php                                   62 -> 63 行

已生成: fixes.patch  (1796 字节)
[通过] git apply --check 通过

[已应用] 已应用到 /tmp/tgt/qzone（-p2）
回滚：cd /tmp/tgt/qzone && git apply -R -p2 .../fixes.patch
```

脚本内部会建一个临时 git 仓库，把你的 `src/` 提交进去，再 `git apply --check` 一遍。
**不通过就直接报错退出**，不会给你一个坏补丁。

常用参数：

| 参数 | 用途 |
|---|---|
| `--apply-to DIR` | **推荐**。生成后直接应用到真实项目，自动试 `-p1..-p6` 找到能用的层级，并打印回滚命令 |
| `--strip 1` | 手动裁剪路径层级（`--apply-to` 已能自动处理，一般不用） |
| `-o my.patch` | 指定输出文件名（默认 `fixes.patch`） |
| `--stat` | 只看改了哪些文件，不写 patch |
| `--no-check` | 跳过 `git apply` 自校验 |
| `--allow-delete` | 把「`src` 有、`fixed` 没有」当成删除（默认忽略，防误删） |

**第 3 步：应用并验证**

```bash
cd <项目根目录>
git apply /path/to/fixes.patch        # 没装 git： patch -p1 < /path/to/fixes.patch

# 验证
php -l deploy/app/controllers/AdminController.php
curl <原来的 payload>                  # 确认已经打不进去
```

### 实测记录（qzone 靶场）

| 项目 | 结果 |
|---|---|
| 修复 `AdminController.php` 硬编码密码 + `extract` | 371 → 374 行，`git apply` 通过，`php -l` 通过 |
| 修复 `core/Controller.php` 反序列化 | 62 → 63 行，`unserialize` 加 `allowed_classes => false` |
| CRLF 行尾 | 原文件 374 行全 CRLF、0 裸 LF，补丁后保持一致 |
| 打补丁后起服务 | `GET /` 200、`GET /admin/login` 200、错误密码提示「密码错误」、`ADMIN_PASS` 正确 → 302 进后台、未登录访问后台 → 302 回登录页 |

### 语言相关的坑（`local-ai.md` 里已写进去，AI 会自动遵守）

| 语言 | 坑 | 正确写法 |
|---|---|---|
| PHP | `const X = getenv('A')` → `Fatal error: Constant expression contains invalid operations` | `private static function x(): string { $p = getenv('A'); return is_string($p) ? $p : ''; }` |
| PHP | `$password === self::ADMIN_PASS` 有时序侧信道、null 报错 | `hash_equals(self::adminPass(), (string)$password)` |
| PHP 模板 | 把 `extract()` 的变量搬到 `$this->xxx` → 模板 undefined variable | `extract()` 同名再赋值本身无害，直接删 |
| SQL | 只做 `addslashes` / 正则过滤 | PDO `prepare` + 参数绑定 |
| 文件包含 | `str_replace('../')` 黑名单 | 白名单映射 |
| 反序列化 | 只做 base64 解码 | `unserialize($s, ['allowed_classes' => false])` 或换 `json_decode` |

### 备用：临时用在线 AI 怎么办

在线 AI（ChatGPT / Claude 网页版 / 通义）不能写文件，让它按这个格式输出：

```
=== FILE: qzone/deploy/app/controllers/AdminController.php ===
<?php
...完整文件内容，一行都不能省...
=== END FILE ===
```

把整段回复存成 `ai.txt`，然后：

```bash
pbpaste > ai.txt                          # macOS；Linux 用 xclip -o > ai.txt
python3 extract_files.py ai.txt           # 拆成 fixed/ 下的真实文件，自动跟随原文件 CRLF/LF
python3 make_patch.py fixed/              # 算行号 + 自校验
```

`extract_files.py` 也兼容 `### FILE: path`、` ```php:path/to/file.php ` 这几种写法；
路径在 `src/` 里找不到时会**跳过并提示**（防止 AI 幻觉出不存在的文件名），确认真需要就加 `--force`。

---

## 五、接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/awdp/session` | 建会话。body：`{name, scan_type, engine, zip(base64) 或 files[], findings[]}`；上限 64 MB |
| `GET` | `/api/awdp/sessions` | 列出最近 20 个会话（`root` + `sessions[]`） |
| `GET` | `/awdp/<id>/` | 目录页 |
| `GET` | `/awdp/<id>/<file>` | 只允许生成的文件名（`bundle.md`/`bundle.txt`/`prompt.txt`/`findings.json`/`tree.txt`/`README.md`/`index.html`） |
| `GET` | `/awdp/<id>/raw?p=src/xxx` | 读单个源文件（`text/plain`） |
| `POST` | `/api/awdp/delete` | 删除会话目录，body `{"id":"..."}` |

返回示例：

```json
{
  "id": "20261108-014828-awdp_test.zip",
  "dir": "/Users/shu/LingOps-AWDP/20261108-014828-awdp_test.zip",
  "url": "http://127.0.0.1:12801/awdp/20261108-014828-awdp_test.zip/",
  "file_count": 74, "finding_count": 97,
  "by_sev": {"critical": 30, "high": 31, "medium": 29, "low": 7},
  "skipped": 0, "bundle_bytes": 40213,
  "links": {"index": "...", "bundle": "...", "bundle_txt": "...", "prompt": "...",
            "findings": "...", "tree": "...", "raw": ".../raw?p=src/"}
}
```

---

## 六、安全边界（务必知道）

1. **只监听 `127.0.0.1`**：扩展后端默认只绑本地回环，同一 WiFi 下的其他人访问不到。
   如果你改成 `--host 0.0.0.0`，等于把**靶场源码**公开到局域网，请自己评估。
2. **在线 AI 拿不到这个链接**：`127.0.0.1` 只对你自己这台机器有效。要让在线 AI 用，只能复制内容/上传文件。
3. **路径穿越已拦**：`raw?p=` 走 `_safe_rel()` + `realpath` 前缀校验，`../`、绝对路径、盘符一律 400。
4. **目录只读**：服务只做 `GET`，没有任何写入/执行接口；源码以 UTF-8 落盘，原始 ZIP 不保留。
5. **会落盘**：每次上传都会在 `~/LingOps-AWDP/` 留一份源码（含硬编码密钥等敏感内容），
   比赛结束请清理：`rm -rf ~/LingOps-AWDP`。
6. 想换存放位置：`LP_AWDP_DIR=/tmp/awdp python3 ext/lp_scan_server.py --port 12801`。

---

## 七、常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 卡片显示「生成失败」 | 扩展后端没起。`./start-ext.sh`，或 `python3 ext/lp_scan_server.py --port 12801` |
| 上传后没弹提示 | 官方页面的文件输入框是动态渲染的，等 2 秒；仍不行就用「🔬 深度审计」面板上传 |
| 提示「压缩包里没有可用的源码文件」 | 只收文本源码（`.php/.java/.go/.py/.js/.aspx` 等），`vendor/`、`node_modules/`、二进制会被跳过 |
| 问题数为 0 | 官方页上传时如果深度审计还没跑完就生成了，点「重新生成」即可 |
| 链接打得开但 AI 读不到 | 在线 AI 读不了 `127.0.0.1`；改用「复制全文源码」或上传 `bundle.md` |
| 想给 AI 单个文件 | `<base>/awdp/<id>/raw?p=src/php/sqli.php` |
| 磁盘占满了 | `rm -rf ~/LingOps-AWDP`；或在 `POST /api/awdp/delete` 里逐个删 |

---

## 八、和官方「补丁包」的关系

官方 Fix 阶段的补丁包是**平台格式**（要提交/部署到靶机），本功能不替代它：

- **AI 修复包** = 给 AI 的输入（源码 + 问题 + 提示词），目的是让 AI 帮你写出补丁；
- **官方补丁包** = 把改好的代码打包提交，拿分。

流程建议：`上传 ZIP → AI 修复包 → 让 AI 给 diff → 自己核对 → 官方 Fix 页面应用/打包`。
AI 给的补丁务必自己复核：它看不到运行环境，`include` 路径、框架版本、`php.ini` 差异都可能踩坑。
