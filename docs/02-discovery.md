# 02 侦察（目标探测）

**入口**：左侧菜单「侦察」→ `/discovery`
**接口**：`POST /api/v1/discovery/hosts`、`GET /api/v1/tasks`、`POST /api/v1/discovery/cancel/:id`、`WS /api/v1/ws/discovery`

侦察是 AWD 开局第一步：**在比赛网段里找出所有存活靶机**。LingOps 按设定的超时与次数做 ICMP 存活探测（后端 `icmpPing`），目标禁 ping 时会显示离线，需要改用端口扫描接口确认。

---

## 1. 前置条件

- 无需任何 Shell/资产，登录即可用；
- 运行 LingOps 的机器必须能路由到目标网段（AWD 一般直连内网）；
- 目标数量建议 **≤ 1000**，前端对超大输入会提示，超过 5000 条会拒绝。

---

## 2. 支持的地址格式

输入框「目标主机地址」**每行一个**，也接受英文/中文逗号、分号分隔（注意：**空格不是分隔符**，`192.168.1.1 192.168.1.2` 会被当成一条无效目标）：

| 格式 | 示例 | 说明 |
|---|---|---|
| 单个 IP | `192.168.1.1` | |
| IP 段（简写） | `192.168.1.10-50` | 等价于 `.10` 到 `.50`，共 41 个 |
| IP + 端口段 | `192.168.1.2:1000-2000` | 主机存活探测仍只测主机，端口段供后续端口扫描接口使用 |
| 域名 | `baidu.com` | 先解析再探测 |
| 域名 + 端口段 | `baidu.com:70-90` | 同上 |

示例（可直接粘贴）：

```
192.168.1.1
192.168.1.10-50
192.168.1.2:1000-2000
baidu.com
baidu.com:70-90
```

> 重复项会自动去重；无法解析的域名会作为失败项计入「离线/超时」。

---

## 3. 操作步骤

1. 打开「侦察」页；
2. 在「目标主机地址」中粘贴目标列表；
3. 点击 **开始探测**；
4. 观察「探测进度」：进度条 + `已完成: N / 总数`，状态为 `探测中...`；
5. 完成后「探测结果」表格展示每台主机：
   - 目标地址（`ip`）
   - 存活状态（在线 / 离线 / 超时）
   - 响应时间（`rtt`，单位 ms）
   - 探测时间（`timestamp`）
6. 顶部统计卡实时显示：目标总数、在线主机、离线主机、超时主机。

### 中途操作

| 按钮 | 作用 |
|---|---|
| 停止探测 | 取消当前任务（后端标记 `cancelled`，已出结果保留） |
| 清空结果 | 只清空当前页面展示，不影响历史任务 |
| 刷新（历史任务区） | 重新拉取任务列表 |
| 批量删除 | 删除选中的历史任务及其结果 |

### 任务不会因切页丢失

探测进行中时，`id / taskId / 目标 / 进度 / 结果` 会写入浏览器 `localStorage`（键名 `lingops_discovery_task`）。**只有 `status=running` 的记录会在回到页面时恢复**并重连 WebSocket；已完成/已取消的任务不会恢复，请到「历史探测任务」查看。关闭标签页不会让后端任务停止，历史任务里能看到最终结果。

---

## 4. 历史探测任务

下半部分是所有 `discovery_scan` 类型任务：

- 列：序号、探测目标、状态、进度、创建时间、操作（删除）；
- 点击行首展开箭头可查看该任务的**详细结果表**；
- 列表每 3 秒自动刷新一次（存在运行中任务时）；
- 支持分页（默认 10 条/页）、多选、批量删除；
- 状态含义：`pending` 排队、`running` 执行中、`completed` 完成、`failed` 失败、`cancelled` 已取消。

历史任务同时会出现在后端 `tasks` 表里，可用 `GET /api/v1/tasks?type=discovery_scan` 查询。

---

## 5. 进阶：端口与服务扫描（API）

UI 只提供主机存活探测，端口/服务扫描通过接口调用：

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:12800/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["token"])')

# 主机存活
curl -s -X POST http://127.0.0.1:12800/api/v1/discovery/hosts \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ip_range":"192.168.1.1\n192.168.1.10-50","timeout":500,"ping_count":1}'

# 端口扫描（参数按后端定义，通常为 targets/ports/timeout）
curl -s -X POST http://127.0.0.1:12800/api/v1/discovery/ports \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"targets":["192.168.1.10"],"ports":"1-1000","timeout":500}'

# 服务识别
curl -s -X POST http://127.0.0.1:12800/api/v1/discovery/services \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"targets":["192.168.1.10"],"ports":"22,80,3306"}'
```

实时进度通过 WebSocket 推送：

```
ws://127.0.0.1:12800/api/v1/ws/discovery?token=<JWT>&discovery_id=<id>
```

消息格式：`{"topic":"discovery_progress","payload":{"status":"running","progress":42,"results":[...]}}`。

---

## 6. 常见问题

**Q：全部显示离线，但我确定机器是通的？**
A：① 确认 LingOps 与靶机在同一网段/有路由；② 目标可能**禁 ping（ICMP 被过滤）**，此时主机探测会判离线，改用第 5 节的端口扫描接口按端口确认；③ 调大 `timeout`（默认 500ms，跨网段可设 1000–2000）。

**Q：进度条卡住不动？**
A：前端 WS 地址硬编码为 `localhost:12800`。如果你从另一台机器访问控制台，实时进度不会推送，但后端任务仍在跑，完成后刷新历史任务即可看到结果。建议直接在跑 LingOps 的机器上打开浏览器。

**Q：能扫公网吗？**
A：技术上可以，但**必须获得授权**。AWD 场景只扫比赛内网段。

**Q：一次能扫多少个？**
A：建议 ≤1000；更多请拆分成多个任务，避免超时和浏览器卡顿。
