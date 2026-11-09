# 17 端口扫描与上传点探测（扩展）

> 这是给 LingOps v0.2 追加的**扩展模块**：在不改动官方二进制的前提下，把「端口扫描 + 服务识别 + 上传点探测」直接挂进 LingOps 界面里。
> 入口位置：左侧菜单 **端口扫描**（在「总览」下面）或右下角蓝色悬浮按钮。

---

## 一、为什么是"扩展"而不是改源码

官方发布包只提供编译好的 `lingops-server` 二进制和打包好的前端，GitHub 仓库里只有 README 和截图，**没有源码**，无法重新编译。

但发布包的前端是**运行时从磁盘读文件**的：

- `frontend/dist/index.html` 每次请求都重新读取 → 可以注入 `<script>`；
- `frontend/dist/assets_v2/` 下任意文件都能被静态访问 → 可以放我们自己的页面和脚本。

所以本扩展的做法是：

```
frontend/dist/index.html              ← 注入 1 行 <script src="/assets_v2/lp-ext/boot.js">
frontend/dist/assets_v2/lp-ext/
├── boot.js                           ← 加悬浮按钮 + 侧边栏菜单项 + 全屏 iframe
└── panel.html                        ← 扫描面板（同源，能直接读 LingOps 登录态）
ext/
├── lp_scan_server.py                 ← 扫描后端（纯标准库 Python，监听 12801）
└── uninstall.sh                      ← 一键卸载
start-ext.sh                          ← 单独启动扫描后端
```

面板和 LingOps 页面**同源**（都是 `127.0.0.1:12800`），所以能直接读 `localStorage["lingops_token"]` 调 `/api/v1/assets`，实现「从资产库导入目标」「把结果写回资产库」。

> 官方升级（替换 `frontend/`）会覆盖 `index.html`，扩展随之失效，重新执行注入即可（见文末「重装」）。

---

## 二、启动

### 方式 A：用 `start.sh`（推荐，两个服务一起起）

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
./start.sh
```

`start.sh` 现在会在启动 LingOps 前，额外拉起扫描后端（12801），日志写到 `/tmp/lingops-scan-ext.log`；按 `Ctrl+C` 会一并结束。

### 方式 B：单独启动扫描后端

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
bash start-ext.sh            # 默认 12801
bash start-ext.sh 12901      # 自定义端口（面板需带 ?api= 参数，见下）
```

启动后自检：

```bash
curl http://127.0.0.1:12801/api/health
# {"ok": true, "version": "1.0.0", "jobs": 0}
```

### 打开面板

浏览器登录 <http://127.0.0.1:12800>，然后任选：

- 左侧菜单点 **端口扫描**；
- 右下角点蓝色 **端口扫描** 悬浮按钮；
- 直接访问 <http://127.0.0.1:12800/assets_v2/lp-ext/panel.html>（独立页，功能相同）；
- 控制台执行 `__lpOpenScan()`。

按 `Esc` 或点遮罩关闭面板。

> 面板顶部显示「扫描服务已连接 · v1.0.0」表示 12801 正常；显示「扫描服务未启动」就是后端没起。

---

## 三、面板怎么用

### 0. 先探活（ICMP + TCP 双探，专治"扫不到靶机"）

> 官方「侦察 → 探测」只发 ICMP echo。**只要目标丢 ICMP（靶机 iptables DROP、云主机安全组、NAT 只映射 80），官方就判它离线**，哪怕它 80 端口是开的。详见文末第八节。

面板第二块卡片就是 **深度探活**：

1. 「探测目标」留空 → 复用上面「扫描目标」输入框；也可单独填（支持 `192.168.1.0/24`、`1.2.3.1-20`）。
2. 「单次超时」内网 0.5~1.0，跨网段 1.5。
3. 「先发 ICMP」默认勾上；**关掉 = 纯 TCP 探活**（目标网络禁 ping 时更快）。
4. 点 **开始探活**，结果表给出每台的判定、探测方式、RTT 和原因说明。
5. 点 **在线主机填入扫描目标** → 直接把这些 IP 灌进上面的扫描框，接着扫端口。

探测顺序：先 ICMP echo → 不通再对 24 个常见端口**并发 TCP connect**（80/443/8080/8443/8000/22/445/3389/21/23/25/110/143/3306/5432/6379/9200/5000/7001/8081/8888/9090/11211/27017）。判定规则：

| 探测方式 | 含义 |
|---|---|
| `ICMP 回包` | 正常主机 |
| `TCP 端口开放` | 丢 ICMP，但某个端口能连上 → **靶机最常见形态** |
| `TCP 拒绝(RST)` | 丢 ICMP，但回了 RST → 主机活着、端口全关 |
| `未响应` | ICMP 无回包 + 端口全超时（可能真离线，也可能全 DROP） |

一个 /24 大约 3~6 秒（96 并发、24 端口全并发）。

**入口**：`侦察 → 探测` 页面「开始探测」旁边也会自动多一个 **深度探活（ICMP+TCP）** 按钮（由 `boot.js` 注入），点它直接打开面板并定位到这块卡片。

### 1. 填目标

支持以下写法（换行或逗号分隔，可混写）：

| 写法 | 说明 |
|---|---|
| `192.168.1.10` | 单个 IP |
| `192.168.1.0/24` | CIDR 网段（上限 1024 台） |
| `192.168.1.1-20` | 短区间 |
| `192.168.1.1-192.168.1.20` | 完整区间 |
| `target.com` | 域名（自动解析 A 记录） |
| `http://1.2.3.4:8080` | 带协议/端口，端口会自动并入待扫列表 |

右侧两个按钮：

- **从资产库导入**：把 LingOps 资产库里所有主机资产的目标填进来（适合"先侦察、再细扫"）；
- **读取剪贴板**：把剪贴板里的 IP 列表贴进来（需要浏览器授权）。

### 2. 选端口

| 预设 | 数量 | 内容 |
|---|---|---|
| Web 常用 | 27 | 80/443/8080/8443/8000/8888/9000/7001/9200… |
| 常用端口 | 51 | Web + 22/21/3389/3306/6379/445/139/1433/5432… |
| Top 100 | 104 | 内网高频服务端口 |
| 全端口 | 65535 | 1-65535，慢，谨慎用 |

也可以直接手写：`80,443,8000-8100`。

### 3. 参数

| 项 | 默认 | 说明 |
|---|---|---|
| 连接超时 | 1.0s | 单端口 TCP 超时；内网 0.5-1s 足够，跨网段可加到 2-3s |
| 并发线程 | 300 | 同时探测的端口数；全端口扫描建议 500-800 |
| 上传点探测强度 | 标准 | 快速 12 个路径 / 标准 45 个 / 深度 更多路径 + 目录列举 |

### 4. 四个开关

| 开关 | 默认 | 作用 |
|---|---|---|
| HTTP 探测 | 开 | 取标题、状态码、`Server`、`X-Powered-By`，判断是不是 Web |
| 上传点探测 | 开 | 找上传表单、上传页面、上传接口（**被动**，只 GET/HEAD/OPTIONS） |
| 主动上传测试 | **关** | 真的往疑似上传点 POST 一个测试文件（见「风险提示」） |
| 危险扩展名测试 | **关** | 主动上传时再试 `.php/.jsp/.aspx`，判断能否传可执行文件 |

### 5. 看结果

顶部 5 张卡：存活主机 / 开放端口 / Web 服务 / 上传点 / 高危主机。

结果表每行一台主机，点 **详情** 展开：

- **端口 / 服务**：端口号 + 指纹（SSH/FTP/MySQL/Redis…）+ HTTP 标题；
- **上传点探测**：每条命中的 URL、类型、风险、证据。

底部是运行日志（实时滚动），右上角可 **导出 JSON / CSV**，结果区右上角可 **写入资产库**（按 IP 去重，已存在的跳过，`tags.source=portscan`，`metadata.open_ports` 存端口列表）。

---

## 四、上传点探测原理

### 1. 先判断哪些端口是 Web

- 已知 Web 端口（80/443/8080…）直接探；
- 非标准端口：不在 `KNOWN_NON_WEB` 集合里（排除 22/3306/6379/3389/445 等）就尝试 HTTP，每台主机最多 40 次；
- HTTPS 失败会自动回落 HTTP，反之亦然。

### 2. 再找上传相关特征（被动）

| 类型 | 判定 |
|---|---|
| 上传表单 | HTML 里有 `<input type="file">`，解析出 `action` / `method` / `enctype` / 字段名 |
| 页面特征 | 页面含 WebUploader / UEditor / KindEditor / CKEditor / eWebEditor / CKFinder / el-upload / layui upload / wangEditor / Dropzone / Plupload / SWFUpload / "上传" 字样 |
| 疑似接口 | 首页同源链接里含 `upload` / `file` / `editor` / `attach` 的地址，逐个验证可访问 |
| 目录可列举 | 响应含 `Index of /`（能直接看上传目录内容） |
| 允许 PUT/DELETE | `OPTIONS` 响应 `Allow` 里有 PUT/DELETE（可能直接 PUT 上传） |

### 3. 软 404 基线（关键，防误报）

很多站点（SPA、ThinkPHP、Spring）对**任意路径**都返回 200 的首页，直接扫路径会满屏误报。

本扩展先请求 `http://host:port/lp_<随机>_notfound`，记录**状态码 + 响应长度 + MD5**；之后某个路径的响应如果和这个基线一致（长度差 ±40 字节内），判定为"不存在"，不计入结果。

实测：扫 LingOps 自己（12800，标准强度 45 个路径）误报为 0。

### 4. 主动上传测试（默认关闭）

开启后，对每个已识别的上传端点：

1. 依次尝试字段名 `file` / `upload` / `fileupload` / `upfile` / `img` / `image` / `photo` / `Filedata` / `editormd-image-file` / `files[]`（每端点最多试 4 个）；
2. 内容为纯文本 `LINGOPS_PROBE_<随机串> hello`，文件名 `lp_probe.txt`（`危险扩展名测试` 打开时再追加 `.php/.jsp/.aspx`）；
3. 判定成功：返回 JSON 含 `url`/`path`/`src`/`code=0`，或含"成功/ok/success"且不含"失败/error/禁止"；
4. 若回显了可访问的 URL，且下载回来包含探针标记 → 风险升级为 **high**（说明上传真的落地了）。

### 5. 风险分级

| 级别 | 触发条件 |
|---|---|
| 高（high） | 主动上传成功且文件可访问并回显内容；或上传接口允许危险扩展名 |
| 中（medium） | 存在上传表单 / 上传接口 / 目录可列举 / 上传被接受 |
| 低（low） | 仅页面关键字、仅链接提示 |
| —（none） | 未发现 |

---

## 五、命令行用法（不进界面也能扫）

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"

# 只做存活探测（ICMP + TCP 兜底）
python3 ext/lp_scan_server.py --discover 192.168.1.0/24
python3 ext/lp_scan_server.py --discover 192.168.1.0/24 --timeout 0.6 --no-icmp   # 纯 TCP

# 扫一个网段的常用端口 + 上传点探测
python3 ext/lp_scan_server.py --scan 192.168.1.0/24 -p common --upload

# 扫指定端口并做主动上传测试
python3 ext/lp_scan_server.py --scan 10.0.0.5 -p 80,8080,8000-8100 --upload --active-upload

# 输出 JSON 给别的脚本用（默认就是 JSON）
python3 ext/lp_scan_server.py --scan 10.0.0.5 -p web > out.json
# 输出 CSV
python3 ext/lp_scan_server.py --scan 10.0.0.5 -p web --csv > out.csv
```

参数：`--scan` 目标、`-p/--ports` 端口（预设名或列表）、`--timeout`、`--concurrency`、`--upload`、`--active-upload`、`--dangerous-ext`、`--strength quick|standard|deep`、`--csv`（默认输出 JSON）；存活探测单独用 `--discover` + `--no-icmp`。

### HTTP API（可脚本化）

```bash
# 存活探测（ICMP + TCP 兜底）
curl -X POST http://127.0.0.1:12801/api/discover -H 'Content-Type: application/json' \
  -d '{"targets":"192.168.1.0/24","timeout":0.8,"icmp":true}'
# → {"hosts":[{"ip":"192.168.1.3","alive":true,"method":"tcp-open","rtt":6,"port":80}, ...],
#    "stats":{"total":254,"alive":4,"by_icmp":3,"by_tcp":1,"elapsed_ms":5552,...}}

# 建任务
curl -X POST http://127.0.0.1:12801/api/scan -H 'Content-Type: application/json' -d '{
  "targets": "127.0.0.1",
  "ports": "12800,18081",
  "timeout": 1.0,
  "concurrency": 300,
  "do_http": true,
  "upload_detect": true,
  "active_upload": false,
  "dangerous_ext": false,
  "strength": "standard"
}'
# → {"job_id":"0c9fd017df91"}

curl http://127.0.0.1:12801/api/jobs/0c9fd017df91          # 查进度/结果
curl -X POST http://127.0.0.1:12801/api/jobs/0c9fd017df91/cancel
curl "http://127.0.0.1:12801/api/jobs/0c9fd017df91/export?fmt=csv"
```

---

## 六、风险提示（务必读）

1. **主动上传测试会在目标上留下文件**（`lp_probe.txt`，危险扩展名测试会留 `.php` 等）。
   - AWD 比赛里对**对手**机器开启没问题（本来就在打）；
   - 对自己机器、客户生产环境，**默认关闭**，需要时先确认授权并手动清理 `/uploads/lp_probe.txt`。
2. **全端口扫描很吵**：65535 × N 台主机的连接会产生大量日志和告警，内网比赛够用就别开。
3. **并发别拉满**：`并发 1000` + 全端口会打满本机文件句柄和临时端口，报 "Too many open files" 就把并发降到 300 以下，或先 `ulimit -n 4096` 提高上限（macOS 默认已较高，Linux 常见 1024）。
4. **只扫授权范围**：扩展本身不校验目标合法性，扫谁由你决定，责任也在你。

---

## 七、维护

### 卸载

```bash
cd "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64"
bash ext/uninstall.sh
```

会删除 `assets_v2/lp-ext/`、还原 `index.html`（优先用 `index.html.bak-lingops-ext`，没有就剔除注入行）、删除 `ext/` 和 `start-ext.sh`。

### 官方升级后重装注入

替换 `frontend/` 后，`index.html` 被覆盖，注入丢失。重新注入只需在 `</head>` 前加一行：

```html
<script src="/assets_v2/lp-ext/boot.js?v=3" defer></script>
```

并确保 `frontend/dist/assets_v2/lp-ext/`、`ext/` 仍在（升级不会动它们）。改完刷新页面即可，**无需重启 LingOps**。
`?v=3` 是给 `boot.js` 做缓存刷新用的，改过 `boot.js` 就把它 +1；`boot.js` 会自动再加载 `lp-ext/fsfix.js`（文件管理器补丁）。

### 注入文件清单

| 文件 | 作用 |
|---|---|
| `frontend/dist/assets_v2/lp-ext/boot.js` | 入口：悬浮按钮 + 侧边栏菜单 + 加载 fsfix |
| `frontend/dist/assets_v2/lp-ext/panel.html` | 端口/上传点扫描面板 |
| `frontend/dist/assets_v2/lp-ext/fsfix.js` | WebShell 文件管理器兼容补丁（Windows 目标） |
| `ext/lp_scan_server.py` | 扫描后端（12801） |
| `start-ext.sh` / `ext/uninstall.sh` | 单独启动 / 卸载 |

### 常见问题

| 现象 | 排查 |
|---|---|
| 面板顶部「扫描服务未启动」 | `curl http://127.0.0.1:12801/api/health`；没起就 `bash start-ext.sh`；端口被占用会启动失败，看 `/tmp/lingops-scan-ext.log` |
| 界面没有「端口扫描」菜单 | 强制刷新（`Cmd+Shift+R`）；确认 `index.html` 里有 `lp-ext/boot.js`；F12 控制台看是否 404 |
| 结果全是 0 | 目标不通 / 超时太短 / 端口选错；先 `curl -v http://目标:端口` 手测 |
| 上传点误报多 | 提高强度到「深度」会更多误报；反过来用「快速」；SPA 站点依赖软 404 过滤，若站点随机内容则仍可能误报 |
| 「写入资产库」提示未登录 | 面板必须从 LingOps 页面内打开（同源才有 token），独立标签页打开需先登录 LingOps |
| 扫本机端口全 close | 目标写 `127.0.0.1`；LingOps 只监听 127.0.0.1 时，扫 `192.168.x.x` 是扫不到的 |
| 官方「探测」说靶机离线，但浏览器能打开它 | 靶机丢 ICMP（只放通 80）。用面板的**深度探活**或 `--discover`，见第八节 |

---

## 八、为什么官方「探测」扫不到靶机（ICMP vs TCP）

**结论：不是 bug，是两边对"在线"的定义不同。**

| 工具 | 存活判定 | 说明 |
|---|---|---|
| `nmap -sn`（非 root / macOS） | TCP SYN 打到 80、443 | 没有 raw socket 权限时 nmap 退化成 TCP 探测 |
| LingOps `/discovery/hosts` | **只发 ICMP echo** | 接口只有 `ip_range` / `timeout` / `ping_count`，没有 TCP 选项 |

实测证据（`192.168.1.3` 是靶机，`.4` 是手机）：

```bash
nmap -sn --reason 192.168.1.1-4
# 192.168.1.1  syn-ack      ← 80 开着
# 192.168.1.2  conn-refused ← 本机
# 192.168.1.3  syn-ack      ← 80 开着（nmap 认定在线）
# 192.168.1.4  （无输出）    ← 没有 80/443，nmap 漏掉

ping -c 3 192.168.1.3     # 100.0% packet loss  ← ICMP 全丢
ping -c 3 192.168.1.4     # 有回包（60~250ms）  ← LingOps 能扫到它
traceroute 192.168.1.3    # 全是 *              ← ICMP/UDP 都被丢
nc -z -v 192.168.1.3 80   # succeeded           ← 只有 TCP 80 通
```

所以：

- `.3`：**只放通 TCP 80、丢弃全部 ICMP** → LingOps 判离线、nmap 判在线；
- `.4`：**只回 ICMP、没有 80/443** → LingOps 判在线、nmap 漏掉；
- 把两边的结果**并起来**才是真相：`.1 .2 .3 .4` 全在线。

本扩展的「深度探活」正是这个并集：ICMP 通就记 ICMP，ICMP 不通再拿 24 个常见端口做 TCP connect，连上或收到 RST 都算在线。实测同一网段输出：

```
共 254 个 · 在线 4（ICMP 3 / TCP 1）· 3184 ms
192.168.1.1  在线  ICMP 回包      5 ms
192.168.1.2  在线  ICMP 回包      1 ms
192.168.1.3  在线  TCP 端口开放    7 ms   ← 丢弃 ICMP，但 TCP 80 可连接 → 靶机常见形态
192.168.1.4  在线  ICMP 回包     244 ms
```

> 官方 `/discovery` 的 ICMP 逻辑在 Go 二进制里，前端改不了。所以要么用这里的扩展探活，要么在官方侦察页**直接填单个 IP**（不填网段就不需要探活）。
