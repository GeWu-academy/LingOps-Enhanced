# 11 AWDP · Break 阶段（攻击）

**入口**：左侧菜单「AWDP」→「Break 阶段」→ `/awdp/break`
**接口前缀**：`/api/v1/awdp` 与 `/api/v1/break`

Break 阶段 = **打**。用内置知识库快速发现目标源码漏洞、生成 payload、执行利用、绕过 WAF。

---

## 1. 页面结构

```
Break 阶段                          [导入知识库] [导出知识库]
统计卡：Break 扫描任务 / 当前语言 / Payload 条目 / 利用 / 绕过条目
Tabs：
  漏洞发现 | Payload 构造 | 漏洞利用 | WAF 绕过
```

内置数据（首次启动已灌入）：Payload **26** 条、利用 **21** 条、WAF 绕过 **24** 条，均标记「内置」。

---

## 2. 漏洞发现

左右分栏：左侧源码输入，右侧扫描结果。

**语言**：PHP / Python / Java / Node.js / Go（源码包扫描可自动识别为「混合」）。

**输入方式**：

1. **粘贴代码**：直接写/贴到编辑器（带行号，等宽字体）；
2. **上传文件 / ZIP**：
   - 单文件（`.php .phtml .php3 .php4 .php5 .inc .py .pyw .java .jsp .jspx .js .ts .go`）→ 读入编辑器，走**快速扫描**；
   - `.zip` / `.tar.gz` / `.tgz` → 提交为**后台扫描任务**（`scan_type=break`），大工程用这个；
3. **开始扫描**：调用 `POST /awdp/quick-scan {code, language}`，结果直接回显。

> 注意：ZIP 不能直接走快速扫描，会提示「ZIP 源码包请先上传为后台扫描任务」。

**扫描结果**：

- 顶部统计：总命中 / 高危 / 中危 / 低危；
- 多文件任务先显示「可疑文件」表（文件、语言、命中数、高危数、进入单文件）；
- 明细表列：漏洞类型、风险等级、文件:行号、命中规则、代码片段；
- 点击行/「进入单文件」→ 左侧高亮命中行（红底行号）；
- 点明细打开「漏洞详情」：漏洞类型、风险等级、命中位置、命中规则、修复摘要、命中语句。

**后台任务列表**：

| 列 | 说明 |
|---|---|
| 任务 | 名称 + 输入类型（ZIP/tar.gz 源码包 / 源码文件） |
| 状态 | 排队中 / 扫描中 / 已完成 / 失败 |
| 进度 | 进度条 + 当前文件 |
| 语言 | 识别或指定 |
| 命中数 / 高危 / 文件数 | 统计 |
| 操作 | 查看结果 / 查看详情；删除 |

---

## 3. Payload 构造

按「语言 + 漏洞类型」筛选，手风琴展开条目：

- 头部：语言标签、漏洞类型标签、标题、「内置」标记；
- 内容：说明 + 只读代码框（等宽）；
- 操作：**复制**、**编辑**、**删除**；
- 右上：`[语言筛选] [漏洞类型筛选] [刷新] [新增条目]`；
- 超过 12 条分页。

**新增/编辑表单**：

| 字段 | 必填 | 说明 |
|---|---|---|
| 标题 `title` | ✅ | |
| 语言 `language` | ✅ | php/python/java/nodejs/go |
| 漏洞类型 `category` | ✅ | 见下表 |
| 说明 `description` | ❌ | 用法、前置条件、注意事项 |
| 内容 `body` | ✅ | payload 原文 |

**漏洞类型枚举**：SQL 注入 `sqli`、命令执行 `rce`、XSS、SSTI、XXE、文件上传 `upload`、文件包含/路径穿越 `lfi`、反序列化、SSRF、NoSQL 注入、原型污染、压缩包路径穿越、JWT/认证、认证绕过。

---

## 4. 漏洞利用

按语言筛选，条目结构同上（语言标签 + 标题 + 内置标记 + 说明 + 命令/片段 + 复制/编辑/删除）。

**表单字段**：

| 字段 | 必填 |
|---|---|
| 标题 `title` | ✅ |
| 语言 `language` | ✅ |
| 说明 `description` | ❌ |
| 命令 / 片段 `body` | ✅ |

这里放**完整利用链**：curl 命令、Python 脚本、反弹 shell 一行流等。

---

## 5. WAF 绕过

按**漏洞类型**筛选（不是语言）。条目头部显示目标类型标签 + 标题。

**表单字段**：

| 字段 | 必填 |
|---|---|
| 标题 `title` | ✅ |
| 漏洞类型 `target` | ✅ |
| 说明 `description` | ❌ |
| 内容 `body` | ✅ |

典型内容：大小写混写、注释切割、`%00` 截断、分块传输、Unicode 编码、双重 URL 编码、等价函数替换（`system` → `popen`/反引号）。

---

## 6. 知识库导入 / 导出

- **导出知识库**：`GET /break/export` 下载 JSON（payloads + exploits + bypasses）；
- **导入知识库**：选择 `.json` → `POST /break/import`，合并/覆盖同 ID 条目；
- 用途：赛前把团队积累的 payload 打包分发，或赛后备份。

---

## 7. 相关接口

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/awdp/quick-scan` | 快速扫描 `{code, language}` |
| POST | `/awdp/scan-upload` | 后台扫描（multipart：`file`、`scan_type=break`、可选 `language`） |
| GET | `/awdp/scan-jobs?scan_type=break` | 任务列表 |
| GET | `/awdp/scan-jobs/:id` | 任务详情 + findings |
| DELETE | `/awdp/scan-jobs/:id` | 删除任务 |
| GET/POST | `/break/payloads` | 列表 / 新增 |
| PUT/DELETE | `/break/payloads/:id` | 更新 / 删除 |
| GET/POST | `/break/exploits` | 同上 |
| PUT/DELETE | `/break/exploits/:id` | |
| GET/POST | `/break/bypasses` | 同上 |
| PUT/DELETE | `/break/bypasses/:id` | |
| GET | `/break/export` | 导出 JSON |
| POST | `/break/import` | 导入 JSON |

curl 示例：

```bash
TOKEN=...
# 快速扫描一段 PHP
curl -s -X POST http://127.0.0.1:12800/api/v1/awdp/quick-scan \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"language":"php","code":"<?php eval($_POST[1]); ?>"}'

# 上传源码包
curl -s -X POST http://127.0.0.1:12800/api/v1/awdp/scan-upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@src.zip" -F "scan_type=break" -F "language=php"
```

---

## 8. 实战流程

```
1. 拿到目标源码（备份泄露 / git / 上传点 / 对手机器）
2. 上传 ZIP → 后台扫描，或贴关键文件快速扫
3. 看高危命中：rce / upload / sqli / deserialization 优先
4. 到「Payload 构造」找对应 payload，按目标参数改
5. 到「漏洞利用」拿完整利用命令，打点
6. 被 WAF 拦 → 「WAF 绕过」换编码/等价写法
7. 拿到 shell → 去「Shell 管理」添加 → 「Flag 读取」挂任务
```

---

## 9. 常见问题

**Q：扫描结果为空？**
A：语言选错（PHP 代码选了 Java）；或代码太短/被截断；ZIP 请走后台任务。

**Q：上传 ZIP 后一直排队？**
A：后台任务是串行/有限并发，等前一个完成；看「进度」里的当前文件。

**Q：内置条目删了能恢复吗？**
A：可以。删除只影响当前库，用「导入知识库」导入官方 JSON 或从备份恢复；升级/重装会重新灌入。

**Q：能扫二进制/加密源码吗？**
A：不能，只做源码静态规则匹配。加密/混淆代码需先解密。

**Q：扫描会不会打目标？**
A：不会。这里只做**本地源码静态分析**；真正的利用要你自己在「漏洞利用」里执行。
