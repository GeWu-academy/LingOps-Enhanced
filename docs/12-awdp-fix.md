# 12 AWDP · Fix 阶段（防守/修补）

**入口**：左侧菜单「AWDP」→「Fix 阶段」→ `/awdp/fix`
**接口前缀**：`/api/v1/awdp`

Fix 阶段 = **修**。扫自己源码找漏洞 → 查知识库拿修复方案 → 生成 `patch.sh` 一键打补丁。

> 页面说明原话：**漏洞扫描是主入口；漏洞知识库负责定义语义；扫描规则负责定义检测方式。**

---

## 1. 页面结构

```
AWD Fix                            [导入知识库] [导出知识库] [刷新内置知识]
统计卡：知识条目 / 启用规则 / 当前语言可用规则 / 本次命中文件
Tabs：漏洞扫描 | 漏洞知识库 | 扫描规则 | Patch 工作台
```

内置数据：漏洞知识 **1047** 条（含 900 条 2020–2026 年 NVD 采集的真实 CVE）、扫描规则 **759** 条（首次启动自动灌入，可「刷新内置知识」重置）。

---

## 2. 漏洞扫描

与 Break 的「漏洞发现」类似，但结果直接关联**修复知识**。

**输入**：
- 选择语言（PHP/Python/Java/Node.js/Go）；
- 粘贴源码，或「上传文件 / ZIP」（ZIP 走后台任务，单文件走快速扫描）；
- 「开始扫描」→ `POST /awdp/quick-scan`；
- 「刷新任务」更新后台任务列表。

**扫描结果表**：

| 列 | 说明 |
|---|---|
| 文件 | 点击进入单文件并高亮 |
| 行号 | 命中行 |
| 漏洞类型 | sqli/rce/xss/... |
| 风险等级 | 严重/高危/中危/低危 |
| 命中语句 | 代码片段 |
| 命中规则 | 规则名 + 规则 code |
| 关联知识 | 绑定的知识条目名，未绑定显示「未绑定」 |
| 修复摘要 | 一句话修复建议 |
| 操作 | 漏洞详情 / 查看知识 / 查看规则 |

**漏洞详情弹窗**：漏洞类型、风险等级、命中位置、命中规则、成因说明、比赛利用提示、危险函数标签、修复摘要、**快速修复**、**稳妥修复**。

**后台任务表**：任务（源码文件 / ZIP 源码包）、状态（排队中/扫描中/已完成/失败）、进度、语言、命中数、高危、文件数、错误信息、操作（查看结果/查看详情、删除）。

---

## 3. 漏洞知识库

列表：漏洞名称、分类、语言、风险等级、关联规则数、累计命中、修复摘要、操作（编辑 / 用它建规则 / 删除）。

筛选：语言、分类；按钮：导出、新建知识。

**新建/编辑表单**：

| 字段 | 必填 | 说明 |
|---|---|---|
| 漏洞名称 `name` | ✅ | |
| 分类 `category` | ✅ | 14 类，见 11 篇 |
| 语言 `language` | ✅ | php/python/java/nodejs/go |
| 风险等级 `severity` | ✅ | critical/high/medium/low，默认 high |
| 启用 `is_active` | — | 开关 |
| 成因说明 `description` | ❌ | 漏洞原理 |
| 危险函数（每行一个）`danger_functions` | ❌ | 如 `eval`、`system`、`assert` |
| 比赛利用提示 `exploit_tip` | ❌ | 对手可能怎么打 |
| 修复摘要 `fix_summary` | ❌ | 一句话 |
| 快速修复 `fix_fast_method` | ❌ | 应急改法（可能影响业务） |
| 稳妥修复 `fix_secure_method` | ❌ | 推荐改法 |
| 修复代码示例 `fix_code_example` | ❌ | 改前/改后代码 |

点列表里的「建规则」图标，会把名称/语言/分类/等级/知识 ID 带入规则表单，快速绑定。

---

## 4. 扫描规则

列表：规则 ID（code 样式）、规则名称、语言、分类、类型、风险等级、优先级、绑定知识、操作（编辑/删除）。

筛选：语言、分类、来源（内置/自定义）；按钮：导出、新建规则。

**规则类型**：

| 值 | 含义 |
|---|---|
| `regex` 正则匹配 | 用正则匹配源码 |
| `keyword` 危险函数 | 关键字/函数名匹配 |
| `taint` 污点传播 | 污点分析（内置规则为主） |

**新建/编辑表单**：

| 字段 | 必填 | 说明 |
|---|---|---|
| 规则名称 `name` | ✅ | |
| 规则 ID `rule_id` | ❌ | 留空自动生成 `custom-<lang>-<cat>-<ts>` |
| 语言 `language` | ✅ | |
| 分类 `category` | ✅ | 选项来自已有知识库分类 |
| 风险等级 `severity` | ✅ | |
| 规则类型 `type` | ✅ | regex / keyword / taint |
| 优先级 `priority` | ✅ | 数字，默认 5；列表按升序排列（1 最靠前） |
| 置信度 `confidence` | ❌ | low / medium / high，默认 medium |
| 绑定知识 `template_id` | ❌ | 命中后展示哪条修复知识 |
| 启用 `is_active` | — | 开关 |
| 规则说明 `description` | ❌ | |
| 匹配模式 `pattern` | ✅ | 正则或关键字，多行 |

> 写正则时注意：源码是**逐文件**匹配，`pattern` 不要跨文件；用 `(?i)` 忽略大小写；避免灾难性回溯。

---

## 5. Patch 工作台（核心）

目标：把改好的文件 + 自动生成的 `patch.sh` 打成 `patch.tar.gz`，上传到靶机解压执行即可。

### 5.1 上传改动后的文件

- 支持多文件，「选择文件」→ 文件名以标签展示，可单个删除或「清空」；
- 上传后自动**按扩展名识别语言**（`.php/.phtml/.inc` → php；`.py` → python；`.java/.jsp/.jar` → java；`.js/.ts/.mjs/.cjs/.jsx/.tsx` → nodejs；`.go` → go；识别不到默认 php）。

### 5.2 生成配置

| 字段 | 默认 | 说明 |
|---|---|---|
| 语言 | 自动识别 | PHP / Python / Java / Node.js / Go |
| 脚本名 | `patch.sh` | 打包进 tar.gz 的脚本名 |
| 目标路径 | php `/var/www/html`；其他 `/app` | 靶机上代码所在目录 |
| 主文件名（启动入口） | 输入框为空，占位提示 php `index.php`；python `app.py`；java `app.jar`；nodejs `server.js`；go `app` | 重启服务时用；**留空则脚本取最后一个上传文件的文件名** |
| 是否附带重启服务命令 | 关 | 开启后脚本会杀进程并重启 |

切换语言会把目标路径重置为该语言默认值，并清空主文件名输入框（只保留占位提示）。

### 5.3 patch.sh 预览

- 自动生成，可**手动编辑**（编辑后不再被自动覆盖）；
- 右上「复制」「放大」；
- 底部：
  - **下载 patch.tar.gz**：把上传的文件 + patch.sh 打成 gzip tar 包（要求至少 1 个文件且脚本非空）；
  - **下载 patch.sh**：只下脚本。

生成脚本的逻辑（按语言）：

```bash
# PHP：直接 cp，通常无需重启
cp /index.php /var/www/html/index.php
# 如使用 PHP-FPM 可选重启

# Python（带重启）
cp /app.py /app/app.py
ps -ef | grep python | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null
cd /app && nohup python app.py >> /opt/app.log 2>&1 &

# Java（带重启）
ps -ef | grep java | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
cp /app.jar /app/app.jar
cd /app && nohup java -jar app.jar >> /opt/app.log 2>&1 &

# Node.js（带重启）
ps -ef | grep npm | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
ps -ef | grep node | grep -v grep | awk '{print $2}' | xargs kill -9 2>/dev/null || true
cp /server.js /app/server.js
cd /app && nohup node server.js >> /opt/app.log 2>&1 &

# Go（带重启）
kill -9 $(pidof app) 2>/dev/null || true
cp /app /app/app
chmod +x /app/app
nohup /app/app >> /opt/app.log 2>&1 &
```

> 注意 `cp /文件名 目标路径/文件名` 的源路径是**根目录**，说明脚本预期在解压目录执行、且文件平铺在包根。上传前确认文件在包里是平铺的（本工具打包时就是平铺）。

### 5.4 Patch 知识库

页面底部手风琴：

- **Patch 模板（按语言）**：各语言完整模板，可复制；
- **常用命令 & Tips**：杀进程、改权限、注意事项：
  1. 按服务启动用户执行，weblogic 不能 root 启动；
  2. 权限问题可临时 `chmod -R 777 /app/*`；
  3. 先 `cp` 再 `kill`，避免服务中断时间过长。

### 5.5 使用流程

```bash
# 靶机上
tar -xzf patch.tar.gz -C /tmp/patch
cd /tmp/patch
chmod +x patch.sh
./patch.sh
# 验证服务
curl -I http://127.0.0.1/
```

---

## 6. 后端高级能力（UI 未暴露）

Patch 包管理接口（`/awdp/patch/packages`）支持上传、diff、下载、下载 shell、版本列表、回滚；以及 `/awdp/patch/templates`、`/awdp/patch/generate-shell`、`/awdp/patch-drafts`、`/awdp/findings/:id/create-patch-draft`。发布版 UI 只用前端本地生成，未接这些接口，需要时可 curl 调用。

---

## 7. 相关接口

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/awdp/scan` | 源码扫描（fix） |
| POST | `/awdp/scan-upload` | 后台扫描 `scan_type=fix` |
| GET | `/awdp/scan-jobs?scan_type=fix` | 任务列表 |
| GET | `/awdp/scan-jobs/:id` | 详情 |
| GET/POST | `/awdp/knowledge` | 知识列表 / 新建 |
| GET/PUT/DELETE | `/awdp/knowledge/:id` | 详情 / 更新 / 删除 |
| GET | `/awdp/knowledge/export` | 导出 |
| POST | `/awdp/knowledge/import` | 导入 |
| POST | `/awdp/knowledge/refresh` | 刷新内置知识 |
| GET/POST | `/awdp/scan-rules` | 规则列表 / 新建 |
| GET/PUT/DELETE | `/awdp/scan-rules/:id` | |
| GET | `/awdp/scan-rules/export` | 导出规则 |
| POST | `/awdp/scan-rules/import` | 导入规则 |
| POST | `/awdp/reset` | 重置 AWDP 数据（慎用） |

---

## 8. 实战流程

```
1. 备份原始源码（基线管理 → 网站备份）
2. 上传自己源码 ZIP → 漏洞扫描
3. 按高危优先：rce / upload / sqli / deserialization
4. 每条命中点「查看知识」→ 看快速修复 + 稳妥修复
5. 本地改代码，验证功能正常
6. Patch 工作台：上传改好的文件 → 确认语言/路径/入口 → 下载 patch.tar.gz
7. 靶机执行 patch.sh → 回归测试
8. 复扫确认漏洞消失，且没引入新问题
```

**优先级建议**：先修对手已经在打的（看访问日志/WAF 日志），再修高危静态漏洞。

---

## 9. 常见问题

**Q：扫描不出东西？**
A：语言选错、代码被截断、或规则未启用。到「扫描规则」确认该语言有启用规则（统计卡「当前语言可用规则」）。

**Q：知识库/规则被改乱了？**
A：「刷新内置知识」重新灌入内置条目（自定义条目通常保留）；或用「导入知识库」恢复备份 JSON。

**Q：patch.sh 执行后服务没起来？**
A：看 `/opt/app.log`；检查主文件名/目标路径；确认执行用户有权限；先手动 `cp` 再 `kill` 验证。

**Q：ZIP 上传后没结果？**
A：后台任务在跑，看「进度/当前文件」；失败看「错误信息」。

**Q：能一次修多个文件吗？**
A：可以，Patch 工作台支持多文件，脚本会逐个 `cp`。

**Q：Patch 包会覆盖原文件吗？**
A：会，`cp` 直接覆盖。执行前务必在靶机备份原文件（`cp x x.bak`）。
