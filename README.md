# LingOps Enhanced

> 基于 [LingOps（灵控）v0.2.0](https://github.com/zhanglinglingc/lingops/releases/tag/v0.2.0) 的 AWD / AWDP 竞赛平台增强版。
> 官方二进制**未修改**，所有改动都在前端注入层、扩展后端、ARTEX 集成与文档里。

面向 AWD / AWDP 实战：补官方没有的**端口与上传点扫描**、**Flag 自动查找**、**木马免杀**、
**跨行污点深度审计**、**AI 修复包**，并集成 [ARTEX](https://github.com/zhanglinglingc/lingops) 做 LLM 多智能体自治渗透。

---

## 快速开始

### macOS (Apple Silicon)

```bash
unzip LingOps_v0.2_darwin_arm64-enhanced.zip
cd LingOps_v0.2_darwin_arm64
./start.sh
```

### Windows x64

```bash
解压 LingOps_v0.2_win64_enhanced.zip
双击 start.bat
```

> Windows 包**内置便携版 Python 3.11**（`python/` 目录），不用装 Python。
> 想用自己装的：删掉 `python\` 目录，`start.bat` 会自动退回 `python` → `py -3`。

启动后打开 <http://127.0.0.1:12800>，账号 **admin / admin123**（首次登录后请改）。

| 服务 | 端口 | 说明 |
|---|---|---|
| 主服务 | 12800 | Go 二进制，官方前端 + 注入层 |
| 扩展后端 | 12801 | `ext/lp_scan_server.py`，端口/上传点扫描、Flag 猎手、AI 修复包 |
| ARTEX | 8787 | LLM 自治渗透，可选 |
| PostgreSQL | 5433 | ARTEX 的数据源，可选 |

停止：`./stop.sh`（Windows 用 `stop.bat`，按端口杀进程）。

---

## 相对官方的增强

| 模块 | 位置 | 说明 |
|---|---|---|
| **端口与上传点扫描** | 侧边栏「端口扫描」 | ICMP+TCP 双栈探活（解决官方丢 ICMP 的靶机）、端口扫描、服务指纹、Web 探测、**上传点探测** |
| **Flag 自动查找** | `/flag` 页按钮 | 自动遍历常见路径、正则提取 flag、一键加入监控 |
| **木马免杀生成器** | `/attack/trojan` 页 | 三档免杀 + 图片马/图标伪装 + `.htaccess` / `.user.ini` |
| **哥斯拉级木马** | 同上 | XOR/AES/Base64 加密信道 + 五种真实图片马 + `connect.py` / `selftest.php` |
| **AWDP 深度审计** | `/awdp/break`、`/awdp/fix` | **跨行污点分析**，补官方引擎漏报；88 个回归样本可自测 |
| **AI 修复包** | 上传 ZIP 后自动生成 | 源码 + 问题清单落盘 + 本地链接，直接交给本地/在线 AI 修漏洞 |
| **ARTEX 集成** | 侧边栏「ARTEX」 | 全屏内嵌 8787，`start.sh` 一键同起 PostgreSQL + ARTEX，已汉化 |

完整教程见 [`docs/README.md`](docs/README.md)（23 章）。

---

## 仓库结构

```
├── lingops-server          # 官方 Go 二进制（未修改）
├── start.sh / stop.sh      # 一键启动/停止（macOS）
├── start.bat / stop.bat    # 一键启动/停止（Windows）
├── start-ext.sh            # 只启动扩展后端
├── configs/config.yaml     # 配置（端口、JWT 密钥、数据库）
├── frontend/dist/          # 官方前端 + 注入层
│   └── assets_v2/lp-ext/   #   ← 注入的扩展前端（boot.js / awdpplus.js / ...）
├── ext/                    # 扩展后端（Python，纯标准库，零 pip 依赖）
├── artex/                  # ARTEX 二进制 + skills
├── tests/awdp-corpus/      # 88 个回归样本 + oracle 自测工具
├── docs/                   # 23 章教程
└── CHANGELOG.md            # 每个版本改了什么、为什么改
```

---

## 扩展是怎么接进去的

官方前端是个编译过的 SPA bundle，不能改源码。所有扩展都靠 **运行时 DOM 注入**：

```
index.html  →  <script src="/assets_v2/lp-ext/boot.js?v=23" defer>
                     │
                     ├── 往侧边栏塞「端口扫描」「ARTEX」两个菜单项
                     ├── 隐藏官方自带的空「团队」占位菜单
                     └── 点菜单 → 全屏 iframe 加载 panel.html
```

后端扩展在 `ext/lp_scan_server.py`（独立进程，端口 12801），主服务通过 `/api/*` 代理，
所以官方二进制完全不用动。

---

## ⚠️ 部署前必改

这个仓库里**不含**任何运行时数据或密钥，clone 下来需要自己生成：

| 项 | 处理方式 |
|---|---|
| `configs/config.yaml` 的 `auth.jwt.secret` | 换成随机串：`openssl rand -hex 32` |
| `artex/config.json` | 首次运行 `start.sh` 会从 `config.example.json` 生成，**填上 `database.password`** |
| `artex/jwt.key` | 首次运行自动生成，勿外传 |
| `data/lingops.db` | 首次启动自动建库并写入内置知识库 |

`data/`、`artex/data/`、`artex/jwt.key`、`artex/config.json` 已进 `.gitignore` ——
里面有真实资产 IP、WebShell 凭据、MITM CA 私钥，**永远不要提交**。

---

## 已知限制

- **ARTEX 需要 PostgreSQL 16**：`start.sh` 只负责启动不负责安装，macOS 用 `brew install postgresql@16`；
- **端口扫描需要靶机可达**：扩展后端跑在本机，扫内网要保证网络通；
- **Windows 的 Defender** 可能对未签名的 `python.exe` 报「未知发布者」，点「仍要运行」；
- 官方 `/team` 是空占位页（"功能正在开发中"），已由注入层隐藏。

---

## 致谢与授权

- 原项目：[zhanglinglingc/lingops](https://github.com/zhanglinglingc/lingops) v0.2.0
- 本仓库的 `lingops-server`、`artex/artex` 二进制**原样来自官方 release**，未做任何修改；
  上游仓库未声明开源许可证，二进制版权归原作者所有，此处仅作学习与竞赛使用，请勿商用。
- 本仓库自行编写的部分（`ext/`、`frontend/dist/assets_v2/lp-ext/`、`docs/`、`tests/`、启动脚本）可自由使用。

---

## 变更记录

见 [CHANGELOG.md](CHANGELOG.md)。当前版本 **v1.3.2**。
