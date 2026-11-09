# 10 Flag 读取

**入口**：左侧菜单「Flag 读取」→ `/flag`
**接口前缀**：`/api/v1/flag`

> 创建后台任务循环读取目标 Flag 文件，**切换页面不会中断任务**（一个 WebShell 对应一个队伍）。

AWD 抢分核心功能：给每个队伍的 WebShell 挂一个定时读取任务，拿到 flag 立刻提交。

> 💡 **不知道 flag 在哪？** 本页面只能填一个固定路径（默认 `/flag`），没有搜索能力。
> 先用扩展模块「**Flag 查找**」自动搜索目标上的 flag 文件，命中后一键加入监控 →
> 见 [18 Flag 查找](18-flag-hunt.md)。

---

## 1. 页面结构

```
标题 + 说明
统计卡：运行中任务 / 总任务数 / 总读取次数 / 成功读取
提交任务（行内表单）
  [选择 WebShell] [Flag 路径] [读取间隔(秒)] [提交任务] [刷新列表]
任务列表（可批量删除，运行中不可选）
  # | 队伍(WebShell) | Flag 路径 | 间隔 | 状态 | 读取统计 | 最新 Flag | 最近读取 | 操作(详情/停止|删除)
任务详情弹窗
  基础信息 + 读取统计 + 最新 Flag + 读取记录分页表
```

---

## 2. 提交任务

| 字段 | 必填 | 默认 | 说明 |
|---|---|---|---|
| 选择 WebShell `shell_id` | ✅ | — | 只列出**在线**的 WebShell 资产 |
| Flag 路径 `flag_path` | ✅ | `/flag` | 常见：`/flag`、`/flag.txt`、`/root/flag`、`/var/www/html/flag.php` |
| 读取间隔 `interval` | ✅ | `30` | 单位秒，范围 **5–3600** |

点「提交任务」→ 后端创建循环任务并立即开始。

**间隔怎么选**：
- 5–10 秒：抢旗阶段，压力大但反应快；
- 30 秒：常规；
- 60 秒以上：机器多、怕被对手发现异常请求时。

**路径怎么找**：先在该 WebShell 的终端里 `ls /`、`find / -maxdepth 3 -name '*flag*' 2>/dev/null`，确认路径再建任务。

---

## 3. 任务列表

| 列 | 说明 |
|---|---|
| # | 任务 ID |
| 队伍 (WebShell) | 资产名称 |
| Flag 路径 | 读取目标 |
| 间隔 | `N秒` |
| 状态 | 运行中（绿）/ 已停止（灰）/ 失败（红） |
| 读取统计 | 总 / 成功（绿）/ 失败（红） |
| 最新 Flag | 最近一次成功读取的值，可复制 |
| 最近读取 | 时间 |
| 操作 | 详情；运行中→停止，已停止→删除 |

- 运行中的任务**不能勾选删除**，需先「停止」；
- 「批量删除」只对非运行中任务生效；
- 停止 ≠ 删除：停止保留历史记录，删除清空任务与记录。

---

## 4. 任务详情

弹窗内容：

- **基础信息**：WebShell、Flag 路径、读取间隔、状态（运行中/已停止）、开始时间、最近读取；
- **读取统计**：`总: N | 成功: N | 失败: N`；
- **最新 Flag**：绿色代码块，可一键复制；
- **读取记录**表：读取时间 / 状态（成功·失败）/ Flag 值 或 错误信息；分页，可点「刷新」。

失败记录里的 `error` 是判断问题的关键：
- `file not found` / `No such file` → 路径错；
- `permission denied` → 权限不足；
- `连接失败` / 超时 → 马掉了或网络断；
- 空内容 → 文件存在但为空 / 被 WAF 拦截。

---

## 5. 拿旗后的动作

1. 详情里复制最新 Flag；
2. 到比赛平台提交；
3. 如果平台按队伍计分，确认「一个 WebShell 对应一个队伍」的映射没错；
4. 对手可能会删/改 flag 文件，任务会持续读到新值，不用重建。

---

## 6. 相关接口

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/flag/rules` | 读取规则列表 |
| POST | `/flag/rules` | 新建规则 |
| PUT/DELETE | `/flag/rules/:id` | 更新/删除规则 |
| GET | `/flag/tasks` | 任务列表 |
| POST | `/flag/tasks` | 创建任务 `{shell_id, flag_path, interval}` |
| GET | `/flag/tasks/:id` | 任务详情 |
| POST | `/flag/tasks/:id/stop` | 停止任务 |
| DELETE | `/flag/tasks/:id` | 删除任务 |
| GET | `/flag/tasks/:id?record_page=&record_page_size=` | 任务详情 + 读取记录（分页） |
| POST | `/flag/collect` | 手动采集一次 `{shell_id, flag_path}` |
| POST | `/flag/collect/auto` | 按规则自动采集 `{rule_id}` |
| GET | `/flag/history` | 历史读取记录 |
| GET | `/flag/scoreboard` | 计分板汇总 |
| GET | `/flag/stats` | 统计卡数据 |

curl 示例：

```bash
TOKEN=...
# 建任务
curl -s -X POST http://127.0.0.1:12800/api/v1/flag/tasks \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"shell_id":1,"flag_path":"/flag","interval":10}'

# 看任务
curl -s "http://127.0.0.1:12800/api/v1/flag/tasks?page=1&page_size=20" \
  -H "Authorization: Bearer $TOKEN"
```

---

## 7. 常见问题

**Q：WebShell 下拉是空的？**
A：只显示在线 WebShell。先去「Shell 管理」添加并「测试连接」，状态变在线。

**Q：任务一直失败但马是好的？**
A：路径不对或权限不够。用该马的终端执行 `cat /flag` 验证；`open_basedir` 限制时读不到 Web 根之外的路径。

**Q：能对同一个 WebShell 建多个任务吗？**
A：可以，但没必要，会重复请求。一个队伍一个任务即可。

**Q：重启 LingOps 任务还在吗？**
A：任务配置在 SQLite 里，重启后需确认状态；运行中任务由后端调度，若显示已停止，重新提交即可。

**Q：Flag 变了但页面没更新？**
A：点「刷新列表」，或进详情点「刷新」。间隔没到不会读。

**Q：读到的 flag 是别人的？**
A：说明你拿到的是对手队伍的机器，按比赛规则确认归属再提交。
