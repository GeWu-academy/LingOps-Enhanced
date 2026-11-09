# 06 WebShell 扫描（源码查杀）

**入口**：左侧菜单「防御」→「WebShell 扫描」→ `/defense/webshell`
**接口**：`POST /api/v1/awdp/scan-upload`（`scan_type=webshell`）、`GET /api/v1/awdp/scan-jobs?scan_type=webshell`

用于检查**自己网站源码里是否被对手植入了后门**。上传源码或压缩包，平台按内置规则逐文件扫描，给出文件、行号、命中规则、危险等级和修复建议。

---

## 1. 支持的输入

| 类型 | 说明 |
|---|---|
| ZIP 包 | `.zip`，解压后递归扫描（推荐，最省事） |
| tar.gz 包 | `.tar.gz` / `.tgz` / `.gz` |
| 单个源码文件 | 见下方扩展名 |

支持扩展名：

```
.php .phtml .php3 .php4 .php5 .inc
.py .pyw
.java .jsp .jspx
.js .ts
.go
```

支持语言：**PHP / Python / Java / Node.js / Go**；语言可留空自动识别。

---

## 2. 操作步骤

1. 打开「WebShell 扫描」页；
2. 点 **新建扫描任务**；
3. 在弹窗中：
   - **扫描语言**：可选，留空自动识别；
   - **上传源码文件**：点「选择文件」，选 ZIP/tar.gz 或单个源码；
4. 点 **开始扫描**（`okText`），任务创建成功；
5. 任务出现在「扫描任务」表格，状态 `pending → running → completed`；
   - 上传压缩包会进入**后台任务**，逐个文件扫描，进度列显示百分比和当前文件；
   - 页面每 2.5 秒自动刷新运行中的任务；
6. 点任务行「查看」展开「扫描结果」：
   - 顶部统计：语言、文件数、总问题、高危/中危/低危；
   - 文件分布标签：按文件聚合命中数量，红色表示含 critical/high；
   - 结果表：文件、行号、类型、风险、命中规则、命中语句、操作；
   - 点「详情」看「问题详情」：文件、行号、类型、风险、命中规则、修复建议、代码片段。

---

## 3. 顶部统计卡

| 卡片 | 含义 |
|---|---|
| 扫描任务 | 所有 WebShell 扫描任务数 |
| 运行中 | `pending + running` |
| 已完成 | `completed` |
| 发现问题 | 所有任务 `findings_count` 之和 |
| 高危问题 | 所有任务 `high_risk_count` 之和 |
| 快速入口 | 一键跳转 AWDP 页面 |

---

## 4. 结果怎么读

| 字段 | 说明 |
|---|---|
| 文件路径 | 压缩包内相对路径 |
| 行号 | 命中代码行（`line_number`/`line_start`） |
| 类型 | 后门类型，如一句话、eval 类、回调后门、文件写入等 |
| 等级 | `critical` / `high` / `medium` / `low` |
| 命中规则 | 规则 ID / 规则名 |
| 证据 | 命中的原始片段 |
| 代码片段 | 上下文若干行 |
| 修复建议 | `fix_summary`，告诉你删什么/改什么 |

**处置原则：**

1. **critical/high 先看**：一句话、`eval($_POST)`、`assert`、`base64_decode` 嵌套、`file_put_contents` 写 PHP；
2. 对照文件修改时间，找出比赛开始后新增/改动的文件；
3. 确认是后门就删除；不确定的先隔离（改名/移出 web 目录）；
4. 修完重新扫描一遍，直到 critical/high 清零。

---

## 5. 与其他模块配合

```
WebShell 扫描（发现后门）
      ↓
Shell 管理 → 文件管理（查看/删除/恢复）
      ↓
基线管理 → backup（先备份再清理）
      ↓
基线管理 → clean_backdoor（批量清理，dry_run 先看）
      ↓
WAF 管理（部署软 WAF，挡住下一波）
```

---

## 6. 进阶：脚本化调用

页面背后走的是 AWDP 扫描任务接口（`scan_type=webshell`）：

```bash
# 1. 上传源码文件/压缩包，创建后台扫描任务
curl -s -X POST http://127.0.0.1:12800/api/v1/awdp/scan-upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@./www.zip" \
  -F "scan_type=webshell" \
  -F "language=php"

# 2. 任务列表 / 任务详情（含 findings）
curl -s "http://127.0.0.1:12800/api/v1/awdp/scan-jobs?scan_type=webshell&page_size=20" \
  -H "Authorization: Bearer <token>"
curl -s "http://127.0.0.1:12800/api/v1/awdp/scan-jobs/1" \
  -H "Authorization: Bearer <token>"

# 3. 删除任务
curl -s -X DELETE "http://127.0.0.1:12800/api/v1/awdp/scan-jobs/1" \
  -H "Authorization: Bearer <token>"
```

> 后端另有 `/webshell/scan*`、`/webshell/ssh-assets`、`/webshell/download-source` 等路由，但当前前端页面没有使用，行为以实际版本为准。

## 7. 常见问题

**Q：提示「不支持的文件类型」？**
A：检查扩展名是否在白名单内；把整站打成 ZIP 最稳妥（注意不要包含超大二进制/日志）。

**Q：任务一直 pending？**
A：压缩包过大或文件数过多，后台在排队。看任务进度列的 `current_file`；必要时拆分压缩包。

**Q：扫描完成但没发现问题，可我确信有马？**
A：① 马可能是无特征/内存马（无文件落地）；② 规则未覆盖该写法，去「AWDP Fix → 扫描规则」新增规则；③ 用「基线管理 → file_monitor」对比文件变化。

**Q：误报太多？**
A：正常业务里的 `eval`、`include` 也会命中。结合文件路径、修改时间、是否用户可控输入判断，不要无脑删。

**Q：扫描会修改我的文件吗？**
A：不会。扫描是只读的，删除/修复需要你手动操作。
