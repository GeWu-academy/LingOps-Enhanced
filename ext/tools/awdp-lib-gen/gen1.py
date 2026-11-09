import json, os
OUT = "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64/ext/tools/awdp-lib-extra"

def R(rid, name, typ, pat, sev="high", pri=2, desc=""):
    return {"rule_id": rid, "name": name, "type": typ, "pattern": pat,
            "severity": sev, "priority": pri, "description": desc}

def T(name, cat, lang, sev, desc, danger, patterns, sources, rules, fast, secure,
      example, exlang, summary, tip, waf, deps, wl, bl, fw, bypass, fp, tags, refs,
      framework=""):
    return {
        "name": name, "category": cat, "language": lang, "framework": framework,
        "severity": sev, "description": desc,
        "danger_functions": danger, "code_patterns": patterns, "input_sources": sources,
        "match_rules": rules,
        "fix_fast_method": fast, "fix_secure_method": secure,
        "fix_code_example": example, "fix_code_language": exlang, "fix_summary": summary,
        "exploit_tip": tip, "waf_template": waf, "waf_dependencies": deps,
        "whitelist_rule": wl, "blacklist_rule": bl, "framework_fix": fw,
        "bypass_methods": bypass, "false_positive": fp, "tags": tags, "references": refs,
    }

T1 = []

# ---------------- PHP ----------------
T1.append(T(
 "PHP-CGI 参数注入（CVE-2024-4577 / CVE-2024-8926）", "rce", "php", "critical",
 "Windows 下 PHP-CGI 把 best-fit 映射后的字符（如 0xAD 软连字符）误当成命令行参数分隔符，"
 "攻击者用 ?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input 即可在 php-cgi.exe 上执行任意 PHP 代码。"
 "Linux 侧对应 CVE-2024-8926（Windows-only 修正不完整）。",
 ["php-cgi", "php-cgi.exe", "cgi-fcgi"],
 ["php-cgi", "cgi.force_redirect", "x-cgi"],
 ["REMOTE_ADDR", "QUERY_STRING", "REDIRECT_STATUS"],
 [R("kbcve-4577-1", "PHP-CGI 软连字符参数注入", "regex",
    r"(?i)(php-cgi|php-cgi\.exe)[^\n]{0,80}(-d\s|allow_url_include|auto_prepend_file)", "critical", 1,
    "请求行/配置中出现 php-cgi 配合 -d 参数或软连字符 0xAD"),
  R("kbcve-4577-2", "auto_prepend_file 注入", "regex",
    r"(?i)auto_prepend_file\s*=\s*(php://input|data://|/tmp/|\.\.)", "critical", 1,
    "auto_prepend_file 指向可写/流包装地址"),
  R("kbcve-4577-3", "cgi.force_redirect 关闭", "keyword",
    r"cgi\.force_redirect\s*=\s*(0|Off)", "high", 3, "关闭 force_redirect 后 CGI 可直接被外部调用")],
 "升级 PHP ≥ 8.3.8 / 8.2.20 / 8.1.29；临时缓解在 httpd.conf 增加\nRewriteRule ^ - [E=REDIRECT_STATUS:200] 并禁用 php-cgi 目录直接访问。",
 "迁移到 php-fpm（非 CGI 模式）并绑定 127.0.0.1:9000；Web 服务器禁止 .php 目录穿越与 %AD 等非 ASCII 路径；\n"
 "用 try_files $uri =404; 兜底，配合 open_basedir 与 disable_functions 收敛影响面。",
 "# httpd.conf / .htaccess 临时缓解\nRewriteEngine On\nRewriteCond %{QUERY_STRING} ^%ad [NC]\nRewriteRule .* - [F,L]\n\n"
 "# php.ini\ncgi.force_redirect = 1\nexpose_php = Off",
 "apache",
 "Windows 下 PHP-CGI 字符映射绕过导致参数注入 → RCE，必须升级到修复版本。",
 "GET /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1\n"
 "Content-Length: 32\n\n<?php system('whoami');?>",
 "location ~ \\.php$ {\n  if ($args ~* \"%ad\") { return 403; }\n  fastcgi_pass 127.0.0.1:9000;\n}",
 "", "", "%ad,allow_url_include,auto_prepend_file,php-cgi",
 "升级 PHP；无法升级时用 Apache Rewrite 拦截 %AD 查询串，并在 WAF 阻断 php://input 出现在参数名中。",
 ["%AD → %25AD 双重编码", "0xAD 大小写混写 %ad/%AD", "+ 与 %20 混用分隔参数"],
 "误报：正常业务不会在查询串使用 %AD 或 auto_prepend_file。",
 "cve-2024-4577,php-cgi,rce,windows",
 ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577", "https://devco.re/blog/2024/06/07/php-cgi-cve-2024-4577/"],
 framework="php-cgi"))

T1.append(T(
 "PHP-FPM 路径信息下溢（CVE-2019-11043）", "rce", "php", "critical",
 "nginx 的 fastcgi_split_path_info 配置缺陷配合 PATH_INFO 尾部换行，使 FPM 的 env_path_info 指针下溢，"
 "可改写 FPM 内存中的 fastcgi 变量从而执行任意代码（经典 PHuiP-FPizdaM）。",
 ["fastcgi_pass", "php-fpm", "fpm"],
 ["fastcgi_split_path_info", "PATH_INFO", "try_files"],
 ["REQUEST_URI", "PATH_INFO"],
 [R("kbcve-11043-1", "nginx PATH_INFO 配置缺陷", "regex",
    r"fastcgi_split_path_info\s+\^(.+?)\\\.php", "high", 2,
    "split_path_info 正则未锚定结尾，易受换行截断"),
  R("kbcve-11043-2", "缺少 try_files 兜底", "regex",
    r"location\s+~\s+[^\{]*\\\.php[^\{]*\{[^}]{0,200}fastcgi_pass", "high", 2,
    "fastcgi 段落内没有 try_files $uri =404，可被构造不存在的 .php 路径"),
  R("kbcve-11043-3", "fastcgi_param PATH_INFO 未过滤", "keyword",
    r"fastcgi_param\s+PATH_INFO\s+\$fastcgi_path_info", "medium", 3,
    "直接透传 PATH_INFO 未做换行过滤")],
 "# nginx 加一行兜底即可阻断\nlocation ~ [^/]\\.php(/|$) {\n    try_files $uri =404;\n    fastcgi_pass 127.0.0.1:9000;\n}",
 "升级 PHP ≥ 7.1.33 / 7.2.24 / 7.3.11；同时把 nginx 的 fastcgi_split_path_info 锚定到 $，\n"
 "并把 PATH_INFO 白名单化（只允许 [A-Za-z0-9_\\-/\\.]+）。",
 "location ~ [^/]\\.php(/|$) {\n    try_files $uri =404;\n    fastcgi_split_path_info ^(.+?\\.php)(/.*)$;\n"
 "    fastcgi_param PATH_INFO $fastcgi_path_info;\n    fastcgi_pass 127.0.0.1:9000;\n}",
 "nginx",
 "FPM PATH_INFO 下溢可直接 RCE，加 try_files 兜底 + 升级 PHP 双保险。",
 "python3 phuip-fpizdam.py http://target/index.php\n# 成功后 http://target/index.php?a=id",
 "location ~ [^/]\\.php(/|$) { try_files $uri =404; }", "", "", "%0a,path_info,fastcgi_split_path_info",
 "升级 PHP 并补 try_files；WAF 阻断 URL 中裸 %0A/%0D 与超长 PATH_INFO。",
 ["PATH_INFO 尾部 %0A 换行", "大小写 %0a / %0A 混写", "叠加 ../ 增加路径长度"],
 "误报：正常 PATH_INFO 不含换行符。",
 "cve-2019-11043,php-fpm,nginx,rce",
 ["https://nvd.nist.gov/vuln/detail/CVE-2019-11043", "https://github.com/neex/phuip-fpizdam"],
 framework="php-fpm"))

T1.append(T(
 "glibc iconv 溢出 → php://filter 全链 RCE（CVE-2024-2961）", "lfi", "php", "critical",
 "glibc 的 ISO-2022-CN-EXT 转换器存在 1~3 字节堆溢出（CVE-2024-2961），配合 php://filter 的 "
 "convert.iconv 过滤器链可在 PHP 进程内实现任意地址写，进而执行命令；PHP 侧对应 CVE-2024-2961 未单独修复。",
 ["iconv", "php://filter", "convert.iconv"],
 ["php://filter", "convert.iconv", "resource="],
 ["$_GET", "$_POST", "include", "file_get_contents"],
 [R("kbcve-2961-1", "php://filter convert.iconv 链", "regex",
    r"php://filter[^\s'\"]*convert\.iconv", "critical", 1, "出现 php://filter 与 convert.iconv 组合"),
  R("kbcve-2961-2", "iconv 危险编码", "regex",
    r"(?i)(ISO-2022-CN-EXT|CSISO2022CN|ISO2022CNEXT)", "high", 2, "使用存在溢出的 ISO-2022-CN-EXT 编码"),
  R("kbcve-2961-3", "多重过滤器拼接", "regex",
    r"php://filter(/[a-z\-]+=[^/|]+){3,}", "high", 2, "单次请求串联 3 个以上过滤器，典型过滤链利用")],
 "在 php.ini 中禁用危险流：allow_url_fopen=Off、allow_url_include=Off；\n"
 "无法升级 glibc 时用 disable_functions=iconv,iconv_strlen 阻断。",
 "升级 glibc ≥ 2.39-r5 / 发行版补丁（Debian 2.36-9+deb12u6、Ubuntu 2.39-0ubuntu8.2）；\n"
 "应用层对 include/file_get_contents 的参数做 basename 白名单，禁止出现 php:// 协议。",
 "// 不安全\ninclude($_GET['f']);\n// 修复：只允许固定白名单\n$allow = ['home','about','help'];\n"
 "$f = $_GET['f'] ?? 'home';\nif (!in_array($f, $allow, true)) { die('bad'); }\ninclude __DIR__.\"/pages/{$f}.php\";",
 "php",
 "php://filter 过滤链可把任意文件包含升级为 RCE，必须禁止协议前缀并升级 glibc。",
 "$chain = 'php://filter/convert.iconv.UTF8.CSISO2022CN|convert.base64-encode/resource=/etc/passwd';\n"
 "# 结合 cnext-exploits / wrapwrap 生成溢出 payload",
 "location ~ \\.php$ { if ($args ~* \"php://\") { return 403; } }", "",
 "", "php://filter,convert.iconv,ISO-2022-CN-EXT",
 "禁止 php:// 协议进入 include；升级 glibc；WAF 阻断 convert.iconv 关键字。",
 ["大小写 convert.Iconv", "过滤器链中插入 base64 混淆", "用 data:// 替代 php:// 绕过前缀检测"],
 "误报：合法业务极少在参数中出现 php://filter 与 iconv 组合。",
 "cve-2024-2961,glibc,php-filter,rce",
 ["https://nvd.nist.gov/vuln/detail/CVE-2024-2961", "https://www.ambionics.io/blog/php-filter-chains"] ))

T1.append(T(
 "PHP phar:// 反序列化", "deserialization", "php", "high",
 "phar 扩展在解析 phar:// 路径时会自动反序列化归档内的 meta-data，任何接收文件路径的 file 函数"
 "（file_exists、getimagesize、is_dir、filesize 等）都能触发，无需 unserialize。",
 ["phar://", "Phar", "file_exists", "getimagesize"],
 ["phar://", "Phar::", "__destruct"],
 ["$_GET", "$_POST", "$_FILES"],
 [R("kbphp-phar-1", "phar 协议路径", "regex", r"phar://", "high", 1, "出现 phar:// 流包装"),
  R("kbphp-phar-2", "文件函数接收用户输入", "regex",
    r"(file_exists|getimagesize|is_dir|filesize|filemtime|md5_file|stat)\s*\(\s*\$_(GET|POST|REQUEST)", "high", 2,
    "文件元数据函数直接使用用户输入，可触发 phar 反序列化"),
  R("kbphp-phar-3", "POP 链魔术方法", "regex",
    r"function\s+__destruct\s*\([^)]*\)\s*\{[\s\S]{0,300}(unlink|file_put_contents|system|eval|call_user_func)", "medium", 3,
    "魔术方法内存在危险操作，易构成 POP 链")],
 "在入口统一过滤：$f = str_replace(['phar://','php://','file://'], '', $_GET['f']);",
 "对所有文件路径参数使用 basename() + 白名单后缀校验；升级 PHP ≥ 8.0 并设置 phar.readonly=On（默认）；\n"
 "在 disable_functions 中禁用 phar 相关高危函数不可行时，用 open_basedir 限制可读目录。",
 "$f = $_GET['f'] ?? '';\n$f = basename($f);\nif (!preg_match('/^[\\w\\-]+\\.(png|jpg)$/', $f)) { die('bad'); }\n"
 "$p = __DIR__.'/upload/'.$f;\nif (!is_file($p)) { die('404'); }\n",
 "php",
 "phar:// 让任意文件函数变成反序列化入口，路径参数必须 basename + 白名单。",
 "# 生成 phar 并改名为图片上传\n$p = new Phar('/tmp/a.phar');\n$p->startBuffering();\n"
 "$p['x']='<?php ?>';\n$p->setStub(\"GIF89a<?php __HALT_COMPILER(); ?>\");\n"
 "$p['x'] = new Evil();\n$p->stopBuffering();\nrename('/tmp/a.phar','a.gif');",
 "if (preg_match('/(phar|php|file|data|zip):\\/\\//i', $input)) { reject(); }", "",
 "", "phar://,php://,file://,data://",
 "在入口 strip 协议前缀；禁止 phar 反序列化（PHP8 后仍需 phar.readonly 配合）；WAF 拦截 phar:// 与 __HALT_COMPILER。",
 ["phar%3A//", "phar://./", "大写 PHAR://", "多协议嵌套 php://filter/resource=phar://"],
 "误报：业务代码若显式使用 phar 读取归档需放行。",
 "phar,deserialization,pop-chain,php",
 ["https://www.php.net/manual/en/phar.using.object.php"] ))

T1.append(T(
 "PHP-FPM 未授权 FastCGI 直连注入", "rce", "php", "critical",
 "php-fpm 监听 0.0.0.0:9000 且未配置 allowed_clients 时，攻击者可直接构造 FastCGI 协议包，"
 "设置 SCRIPT_FILENAME 为任意路径并配合 auto_prepend_file 执行代码。",
 ["fastcgi", "php-fpm", "SCRIPT_FILENAME"],
 ["listen = 0.0.0.0:9000", "listen.allowed_clients", "SCRIPT_FILENAME"],
 ["9000/tcp"],
 [R("kbphp-fpm-1", "FPM 监听公网", "regex", r"listen\s*=\s*(0\.0\.0\.0|\[::\]):9000", "critical", 1,
    "php-fpm 监听所有网卡，可被外部直连"),
  R("kbphp-fpm-2", "allowed_clients 缺失", "regex", r"listen\.allowed_clients\s*=\s*[0-9]", "high", 2,
    "allowed_clients 未限制为本机"),
  R("kbphp-fpm-3", "SCRIPT_FILENAME 可控", "keyword", r"SCRIPT_FILENAME", "medium", 3,
    "代码中出现 SCRIPT_FILENAME 赋值需审计来源")],
 "php-fpm.conf: listen = 127.0.0.1:9000  # 或 unix socket\nlisten.allowed_clients = 127.0.0.1",
 "改用 unix socket（listen = /run/php/php-fpm.sock）并设置 660 权限 + www-data 属组；\n"
 "容器内把 9000 端口仅暴露给 nginx 所在网络，禁止宿主机端口映射。",
 "; /etc/php/8.2/fpm/pool.d/www.conf\nlisten = /run/php/php-fpm.sock\nlisten.owner = www-data\n"
 "listen.group = www-data\nlisten.mode = 0660\n",
 "ini",
 "FPM 端口暴露等于直接给 RCE，必须只监听本机或 unix socket。",
 "python3 fpm.py -c '<?php echo shell_exec($_GET[1]);?>' -p 9000 127.0.0.1 /var/www/html/index.php\n"
 "# 或使用 gopher:// 从 SSRF 打通 FPM",
 "location ~ \\.php$ { fastcgi_pass unix:/run/php/php-fpm.sock; }", "",
 "", "9000,fastcgi,SCRIPT_FILENAME",
 "只监听 unix socket；防火墙阻断 9000 入站；WAF/IDS 检测裸 FastCGI 二进制流量。",
 ["SSRF → gopher:// 打 9000", "IPv6 [::]:9000 绕过 ACL", "通过 Redis 主从写 FastCGI 包"],
 "误报：仅当配置文本中出现公网监听时告警。",
 "php-fpm,fastcgi,rce,unauth",
 ["https://www.php.net/manual/en/install.fpm.configuration.php"] ))

T1.append(T(
 "PHP 动态函数调用与回调注入", "rce", "php", "high",
 "$func($arg) 形式的可变函数调用、call_user_func、array_map 的第二参数若来自用户输入，"
 "可直接调用 system/eval 等危险函数；常与过滤黑名单配合被绕过。",
 ["call_user_func", "call_user_func_array", "array_map", "usort", "create_function"],
 ["$func(", "call_user_func", "array_map", "preg_replace /e"],
 ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE"],
 [R("kbphp-dyn-1", "可变函数调用用户输入", "regex",
    r"\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(", "critical", 1, "直接用超全局数组作为函数名调用"),
  R("kbphp-dyn-2", "call_user_func 用户输入", "regex",
    r"call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "critical", 1,
    "call_user_func 回调名来自用户输入"),
  R("kbphp-dyn-3", "array_map 回调可控", "regex",
    r"array_map\s*\(\s*\$_(GET|POST|REQUEST)", "high", 2, "array_map 回调名来自用户输入")],
 "白名单：$allow = ['trim','strtolower','htmlspecialchars']; if(!in_array($f,$allow,true)) die;",
 "彻底避免用户输入作为函数名；用 match/switch 显式分发；\n"
 "如需动态分发改用映射数组（$map = ['a'=>'funcA']; $fn = $map[$k] ?? null;）。",
 "$map = ['upper' => 'strtoupper', 'lower' => 'strtolower'];\n$k = $_GET['op'] ?? '';\n"
 "if (!isset($map[$k])) { die('bad op'); }\n$map[$k]($_GET['s']);",
 "php",
 "动态函数调用必须走白名单映射表，绝不能让用户输入直接成为函数名。",
 "?op=system&cmd=id  →  若代码为 $op($_GET['cmd']) 则直接 RCE\n"
 "?f=assert&x=phpinfo()  （PHP<8 assert 是函数）",
 "if (preg_match('/\\$_(GET|POST|REQUEST|COOKIE)\\s*\\[[^\\]]*\\]\\s*\\(/', $code)) { reject(); }",
 "", "", "call_user_func,array_map,usort,assert,eval",
 "改为映射数组分发；WAF 拦截 $_(GET|POST)[...]( 形式。",
 ["大小写 SysTem", "字符串拼接 'sys'.'tem'", "chr(115).chr(121)...", "assert 替代 eval"],
 "误报：框架内部使用 call_user_func 传类方法是正常的，需看参数来源。",
 "php,dynamic-call,rce,callback",
 ["https://www.php.net/manual/en/functions.variable-functions.php"] ))

T1.append(T(
 "PHP 弱类型比较绕过", "auth-bypass", "php", "high",
 "== 松散比较下 \"0e123\" == \"0e456\" 为真、\"admin\" == 0 在 PHP<8 为真，"
 "常见于验证码/密码哈希/签名比对，可绕过登录或支付校验。",
 ["==", "in_array", "strcmp", "md5"],
 ["==", "in_array(", "strcmp("],
 ["$_GET", "$_POST", "$_COOKIE"],
 [R("kbphp-loose-1", "松散比较哈希", "regex",
    r"(md5|sha1)\s*\([^)]*\)\s*==\s*\$", "high", 1, "哈希结果使用 == 比较，可用 0e 魔术哈希绕过"),
  R("kbphp-loose-2", "in_array 未严格", "regex",
    r"in_array\s*\([^,]+,[^,)]+\)\s*[;)]", "medium", 2, "in_array 缺少第三个参数 true"),
  R("kbphp-loose-3", "strcmp 返回值判断", "regex",
    r"strcmp\s*\([^)]*\)\s*==\s*0", "medium", 2, "strcmp 传数组会返回 NULL，NULL==0 为真")],
 "把 == 全部改为 ===；in_array 补第三个参数 true。",
 "统一使用 hash_equals() 做哈希比对；密码校验用 password_verify()；\n"
 "开启 declare(strict_types=1) 并升级 PHP 8（PHP8 起 \"admin\"==0 为 false）。",
 "// 不安全\nif (md5($p) == $stored) {}\n// 修复\nif (hash_equals($stored, md5($p))) {}\n"
 "if (!in_array($v, $allow, true)) { die; }",
 "php",
 "松散比较是 PHP 特有逻辑漏洞，一律使用 === 与 hash_equals。",
 "?password[]=x 使 strcmp 返回 NULL 绕过\n?code=0e123456789 匹配 0e 开头的 MD5",
 "if (preg_match('/(md5|sha1)\\s*\\([^)]*\\)\\s*==/', $code)) { warn(); }", "",
 "", "==,in_array,strcmp,md5",
 "改 === / hash_equals / password_verify；WAF 拦截参数名带 [] 的密码字段。",
 ["0e 魔术哈希（QNKCDZO、240610708）", "传数组让 strcmp 报错返回 NULL", "传数组让 md5 报错返回 NULL"],
 "误报：== 用于整数比较是常见写法，需结合是否涉及认证判断。",
 "php,type-juggling,auth-bypass",
 ["https://www.php.net/manual/en/language.operators.comparison.php"] ))

T1.append(T(
 "PHP 变量覆盖（extract / parse_str / $$）", "auth-bypass", "php", "high",
 "extract($_GET)、parse_str($str)、$$key 循环赋值会把外部输入写成局部变量，"
 "覆盖 $is_admin、$role、$token 等关键变量从而越权。",
 ["extract", "parse_str", "import_request_variables", "$$"],
 ["extract(", "parse_str(", "$$"],
 ["$_GET", "$_POST", "$_REQUEST"],
 [R("kbphp-var-1", "extract 使用超全局", "regex",
    r"extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)", "critical", 1, "extract 直接展开用户输入"),
  R("kbphp-var-2", "parse_str 单参数", "regex", r"parse_str\s*\(\s*[^,)]+\)\s*;", "high", 2,
    "parse_str 第二个参数缺省时会写入当前作用域"),
  R("kbphp-var-3", "可变变量赋值", "regex", r"\$\$\w+\s*=", "medium", 3, "出现 $$ 形式变量赋值")],
 "parse_str($q, $out); 显式指定输出数组；extract 加 EXTR_SKIP 并只从已校验数组提取。",
 "禁止 extract 处理外部输入；改用显式赋值 $id = (int)($_GET['id'] ?? 0)；\n"
 "所有关键判断（is_admin/role）从服务端会话读取，不从请求参数读取。",
 "$q = $_SERVER['QUERY_STRING'] ?? '';\nparse_str($q, $out);\n$id = (int)($out['id'] ?? 0);\n"
 "// 权限一律来自 session\n$isAdmin = !empty($_SESSION['is_admin']);",
 "php",
 "变量覆盖会直接改写权限判断变量，必须禁用 extract/单参 parse_str。",
 "?is_admin=1&role=admin  →  覆盖后进入后台",
 "if (preg_match('/extract\\s*\\(\\s*\\$_(GET|POST|REQUEST)/', $code)) { reject(); }", "",
 "", "extract,parse_str,$$",
 "禁用 extract；parse_str 必须传第二参数；权限判断只读 session。",
 ["parse_str 换行绕过", "$${'G'.'ETS'} 拼接", "register_globals 遗留（PHP<5.4）"],
 "误报：模板引擎内部 extract 渲染变量属正常，需看数据来源。",
 "php,variable-overwrite,auth-bypass",
 ["https://www.php.net/manual/en/function.parse-str.php"] ))

T1.append(T(
 "PHP 任意文件写入 / 日志投毒链", "file-write", "php", "high",
 "file_put_contents、fwrite、error_log 的路径或内容可控时可直接写 webshell；"
 "即使不能写 web 目录，也可投毒 nginx/apache 日志、/proc/self/environ、session 文件，再配合 LFI 执行。",
 ["file_put_contents", "fwrite", "error_log", "fopen", "move_uploaded_file"],
 ["file_put_contents(", "fwrite(", "error_log(", "fopen("],
 ["$_GET", "$_POST", "$_FILES", "User-Agent", "Referer"],
 [R("kbphp-write-1", "文件写入路径可控", "regex",
    r"(file_put_contents|fwrite|error_log)\s*\([^,]*\$_(GET|POST|REQUEST|COOKIE)", "critical", 1,
    "写入目标路径来自用户输入"),
  R("kbphp-write-2", "写入内容可控", "regex",
    r"(file_put_contents|fwrite)\s*\(\s*[^,]+,\s*\$_(GET|POST|REQUEST)", "critical", 1,
    "写入内容来自用户输入，可写入 PHP 代码"),
  R("kbphp-write-3", "日志投毒入口", "regex",
    r"(include|require)(_once)?\s*\(?[^;]*(\\.log|/proc/self|/var/log)", "high", 2,
    "包含日志或 proc 文件，可配合日志投毒 RCE")],
 "写入前 basename + 扩展名白名单；内容做 htmlspecialchars 或 base64 编码。",
 "上传目录放在 webroot 之外并用 nginx location 禁止执行；文件名用 uuid + 固定后缀；\n"
 "写入内容只允许 JSON 结构并用 json_encode 序列化，避免任何 PHP 语法进入文件。",
 "$dir = '/data/uploads/';\n$name = bin2hex(random_bytes(8)).'.json';\n"
 "$data = json_encode(['ua'=>$_SERVER['HTTP_USER_AGENT'] ?? ''], JSON_UNESCAPED_UNICODE);\n"
 "file_put_contents($dir.$name, $data, LOCK_EX);",
 "php",
 "文件写入 + 可执行目录 = webshell；上传目录必须禁执行并随机命名。",
 "# 日志投毒\ncurl -A '<?php system($_GET[1]);?>' http://t/\n# 再 LFI 包含 /var/log/nginx/access.log",
 "location /uploads/ { location ~ \\.(php|phtml|phar)$ { deny all; } }", "",
 "", "file_put_contents,fwrite,error_log",
 "上传目录禁执行；写入内容结构化；WAF 拦截内容中的 <?php 与 <?=。",
 ["日志中插入换行拆分 payload", "base64 + assert 组合", "写入 .user.ini 配合 auto_prepend_file"],
 "误报：正常业务写日志文件属常见，需看路径是否含用户输入。",
 "php,file-write,log-poisoning,webshell",
 ["https://www.php.net/manual/en/function.file-put-contents.php"] ))

T1.append(T(
 "PHP 信息泄露（phpinfo / 调试 / .git）", "info-leak", "php", "medium",
 "暴露 phpinfo()、ThinkPHP/Laravel debug 页面、.git/.svn、composer.lock、备份文件，"
 "会泄露绝对路径、数据库口令、内网地址与源码，是 AWD 中拿第一份凭据的最快路径。",
 ["phpinfo", "var_dump", "print_r", "debug"],
 ["phpinfo(", "APP_DEBUG", "display_errors"],
 ["/phpinfo.php", "/.git/config", "/.env", "/composer.lock"],
 [R("kbphp-info-1", "phpinfo 暴露", "regex", r"phpinfo\s*\(\s*\)", "medium", 2, "代码中存在 phpinfo 调用"),
  R("kbphp-info-2", "调试模式开启", "regex",
    r"(APP_DEBUG|display_errors|app\.debug)\s*[=:]\s*(true|1|On|True)", "medium", 2, "生产环境开启调试"),
  R("kbphp-info-3", "敏感文件路径", "regex",
    r"(\\.env|\\.git/config|composer\\.lock|\\.svn/entries)", "medium", 3, "出现敏感配置文件引用")],
 "删除 phpinfo.php 与测试脚本；.env 移出 webroot；nginx 拦截点开头文件。",
 "生产环境 display_errors=Off、APP_DEBUG=false；用 .gitignore + 部署脚本排除 .git；\n"
 "nginx 增加 location ~ /\\.(?!well-known) { deny all; } 与备份文件后缀拦截。",
 "location ~ /\\.(?!well-known) { deny all; }\nlocation ~* \\.(bak|sql|tar\\.gz|zip|swp|old)$ { deny all; }",
 "nginx",
 "信息泄露本身不致命，但会直接交出数据库口令与源码。",
 "curl http://t/.git/config\ncurl http://t/.env\ncurl http://t/index.php?s=/index/index/phpinfo",
 "location ~ /\\. { deny all; }", "", "", "phpinfo,.env,.git,composer.lock",
 "删除调试入口；nginx 拦截隐藏文件与备份后缀。",
 ["大小写 .ENV", "URL 编码 %2eenv", "路径穿越 /static/../.env"],
 "误报：框架自带健康检查页可能输出版本号，属低危。",
 "php,info-leak,debug,config",
 ["https://owasp.org/www-project-top-ten/"] ))

T1.append(T(
 "PHP CRLF 响应头注入 / 邮件头注入", "crlf", "php", "medium",
 "header()、mail()、setcookie() 的参数若含 \\r\\n，可注入额外响应头（Set-Cookie、Location）或邮件头，"
 "导致会话固定、缓存投毒、开放重定向。",
 ["header", "setcookie", "mail", "mb_send_mail"],
 ["header(", "setcookie(", "mail("],
 ["$_GET", "$_POST", "$_SERVER['HTTP_HOST']"],
 [R("kbphp-crlf-1", "header 拼接用户输入", "regex",
    r"header\s*\(\s*['\"][^'\"]*\$_(GET|POST|REQUEST|SERVER)", "high", 1, "header 值含用户输入"),
  R("kbphp-crlf-2", "mail 头注入", "regex",
    r"mail\s*\([^)]*\$_(GET|POST|REQUEST)", "high", 2, "mail 参数含用户输入，可注入 Bcc/Cc"),
  R("kbphp-crlf-3", "Host 头拼接", "regex",
    r"header\s*\(\s*['\"]Location:[^'\"]*HTTP_HOST", "medium", 2, "Location 使用 Host 头，可被劫持")],
 "header('Location: '.str_replace([\"\\r\",\"\\n\"], '', $u));",
 "对进入响应头的值做 rawurlencode 或 preg_replace('/[\\r\\n]/','',$v)；\n"
 "Location 只允许站内相对路径白名单，禁止使用 Host 头拼接。",
 "$next = $_GET['next'] ?? '/';\n$next = preg_replace('/[\\r\\n]/', '', $next);\n"
 "if (!preg_match('#^/[\\w\\-/]*$#', $next)) { $next = '/'; }\nheader('Location: '.$next);",
 "php",
 "响应头必须过滤 CR/LF，Location 只允许站内相对路径。",
 "?next=%0d%0aSet-Cookie:PHPSESSID=attacker\n?next=//evil.com",
 "if (preg_match('/[\\r\\n]/', $v)) { reject(); }", "", "", "%0d%0a,Location,Set-Cookie",
 "过滤 CR/LF；Location 用相对路径白名单；禁止用 Host 头拼 URL。",
 ["%0d%0a 大小写混写", "%E5%98%8A%E5%98%8D（UTF-8 过长的 CRLF）", "\\r\\n 直接字节"],
 "误报：header() 使用固定字符串不构成风险。",
 "crlf,header-injection,php",
 ["https://owasp.org/www-community/attacks/CRLF_Injection"] ))

# ---------------- Python ----------------
T1.append(T(
 "Python Jinja2 SSTI（含过滤器链利用）", "ssti", "python", "critical",
 "render_template_string 或 Template() 渲染用户输入时，可用 {{7*7}} 探测、"
 "{{cycler.__init__.__globals__.os.popen('id').read()}} 或 attr 过滤器链直接 RCE。",
 ["render_template_string", "Template", "jinja2", "from_string"],
 ["render_template_string(", "Template(", "Environment("],
 ["request.args", "request.form", "request.json"],
 [R("kbssti-jinja-1", "render_template_string 渲染输入", "regex",
    r"render_template_string\s*\(\s*(request\.|f[\"']|.*\+)", "critical", 1, "模板字符串来自请求或拼接"),
  R("kbssti-jinja-2", "Template 直接渲染请求数据", "regex",
    r"Template\s*\(\s*(request\.|user_|input|data)", "high", 2, "Template 构造函数接收外部数据"),
  R("kbssti-jinja-3", "沙箱未启用", "regex",
    r"(jinja2\.)?Environment\s*\(", "medium", 3, "使用普通 Environment 而非沙箱环境")],
 "改用 render_template('固定模板名.html', **ctx)，永不把用户输入当模板。",
 "使用 jinja2.sandbox.SandboxedEnvironment；对模板变量只做值传递；\n"
 "如必须动态模板，用白名单语法解析（如受限的 str.format 或 Mustache）。",
 "from jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()\n"
 "tpl = env.from_string(open('templates/msg.html').read())  # 模板来自文件，不是用户\n"
 "return tpl.render(name=request.args.get('name'))",
 "python",
 "用户输入只能是模板变量，不能是模板本身。",
 "{{7*7}} → 49\n{{config}} 泄露 SECRET_KEY\n"
 "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}\n{{lipsum.__globals__['os'].popen('id').read()}}",
 "if (re.search(r'\\{\\{.*(config|__class__|__globals__|popen)', body)): block()", "",
 "", "__class__,__globals__,popen,config,{{",
 "模板与数据分离；启用 SandboxedEnvironment；WAF 拦截 {{ }} 内危险属性。",
 ["{{ ''|attr('__class__') }}", "{%print(7*7)%}", "{{request|attr('application')}}", "Unicode 全角括号"],
 "误报：模板文件内正常使用 {{ var }} 不算风险。",
 "ssti,jinja2,rce,python",
 ["https://portswigger.net/web-security/server-side-template-injection"] ))

T1.append(T(
 "Python pickle / PyYAML 反序列化", "deserialization", "python", "critical",
 "pickle.loads、cPickle、yaml.load（无 Loader）在解析不可信数据时执行 __reduce__ 指定的函数；"
 "常见于 session cookie、缓存、队列消息、ML 模型文件。",
 ["pickle.loads", "pickle.load", "yaml.load", "dill", "joblib"],
 ["pickle.loads(", "yaml.load(", "cPickle.loads("],
 ["request.cookies", "request.data", "request.files", "redis"],
 [R("kbpy-deser-1", "pickle 反序列化不可信数据", "regex",
    r"(pickle|cPickle|_pickle|dill)\.loads?\s*\(", "critical", 1, "出现 pickle 反序列化调用"),
  R("kbpy-deser-2", "yaml.load 未指定 SafeLoader", "regex",
    r"yaml\.load\s*\(", "high", 2,
    "yaml.load 缺少 SafeLoader，可用 !!python/object 执行代码"),
  R("kbpy-deser-3", "joblib/torch 加载外部文件", "regex",
    r"(joblib\.load|torch\.load)\s*\(", "medium", 3, "模型文件加载同样基于 pickle")],
 "yaml.load(x) → yaml.safe_load(x)；pickle 改用 JSON。",
 "禁止对不可信数据使用 pickle；session 改用 itsdangerous 签名 JSON；\n"
 "必须用 pickle 时加 HMAC 校验并在受限子进程中加载。",
 "import json, hmac, hashlib\nraw = request.cookies.get('state','')\nsig, _, payload = raw.partition('.')\n"
 "if not hmac.compare_digest(sig, hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()):\n"
 "    abort(400)\ndata = json.loads(base64.b64decode(payload))",
 "python",
 "pickle/yaml 反序列化等价于 RCE，必须换成 JSON + 签名。",
 "class E:\n    def __reduce__(self):\n        return (os.system, ('id',))\npickle.dumps(E())\n"
 "yaml: !!python/object/apply:os.system ['id']",
 "if (b'\\x80\\x04\\x95' in body or b'!!python/' in body): block()", "",
 "", "pickle.loads,yaml.load,!!python/object",
 "禁用 pickle 处理外部数据；yaml 一律 safe_load；WAF 拦截 pickle 魔数 80 04 95。",
 ["base64 包裹 pickle", "gzip/zlib 压缩后再 pickle", "protocol=0 文本 pickle 规避魔数检测"],
 "误报：内部可信队列使用 pickle 属常见，需看数据来源。",
 "pickle,deserialization,rce,python",
 ["https://docs.python.org/3/library/pickle.html#restricting-globals"] ))

T1.append(T(
 "Python 命令执行（shell=True / os.system）", "rce", "python", "critical",
 "os.system、subprocess 的 shell=True、os.popen 在参数拼接用户输入时可注入 ; | $() ` 等命令分隔符。",
 ["os.system", "os.popen", "subprocess", "commands"],
 ["os.system(", "shell=True", "os.popen("],
 ["request.args", "request.form", "request.json"],
 [R("kbpy-rce-1", "os.system 拼接输入", "regex",
    r"os\.(system|popen)\s*\([^)]*(request\.|input\(|sys\.argv)", "critical", 1, "os.system 参数含外部输入"),
  R("kbpy-rce-2", "subprocess shell=True", "regex", r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True", "high", 2,
    "shell=True 会经过 shell 解析，需确认参数可信"),
  R("kbpy-rce-3", "format 拼接命令", "regex",
    r"(os\.system|subprocess\.\w+)\s*\(\s*f[\"'][^\"']*\\{", "high", 2, "f-string 直接拼接命令")],
 "改用列表参数 + shell=False：subprocess.run(['ls','-l',path], shell=False, check=True)",
 "shlex.quote 转义 + 参数白名单；更彻底的是用标准库替代外部命令（pathlib、shutil、ipaddress）。",
 "import subprocess, shlex\npath = request.args['path']\n"
 "if not re.fullmatch(r'[\\w./-]{1,64}', path): abort(400)\n"
 "subprocess.run(['ls','-l',path], shell=False, check=True, timeout=5)",
 "python",
 "shell=True 等于把 shell 元字符交给攻击者，必须列表传参。",
 "?host=127.0.0.1;id\n?host=$(id)\n?host=`id`",
 "if (re.search(r'[;|&`$()\\n]', param)): block()", "", "", "os.system,shell=True,subprocess",
 "列表传参 + shell=False；白名单正则；WAF 拦截 shell 元字符。",
 ["$IFS 代替空格", "\\n 换行分隔", "base64 解码后执行", "python -c 二次执行"],
 "误报：shell=True 且参数为常量时不构成风险。",
 "rce,python,command-injection",
 ["https://docs.python.org/3/library/subprocess.html#security-considerations"] ))

T1.append(T(
 "Python 路径穿越（open / send_file / os.path.join）", "lfi", "python", "high",
 "os.path.join(base, user) 在 user 为绝对路径或含 ../ 时会逃出 base；"
 "Flask send_from_directory、open()、zipfile.extract 同理，可读 /etc/passwd、源码、flag。",
 ["open", "send_file", "send_from_directory", "os.path.join", "zipfile.extractall"],
 ["open(", "os.path.join(", "send_file(", "extractall("],
 ["request.args", "request.form", "request.view_args"],
 [R("kbpy-lfi-1", "os.path.join 拼接输入", "regex",
    r"os\.path\.join\s*\([^)]*(request\.|filename|name)", "high", 1, "路径拼接含用户输入"),
  R("kbpy-lfi-2", "open 使用请求参数", "regex",
    r"open\s*\(\s*(request\.|.*\+.*request\.)", "high", 1, "open 路径来自请求"),
  R("kbpy-lfi-3", "extractall 未校验", "regex", r"extractall\s*\(", "medium", 2,
    "zip 解压未校验条目路径，存在 zip slip")],
 "p = os.path.realpath(os.path.join(base, name)); if not p.startswith(base+os.sep): abort(403)",
 "使用 pathlib + resolve() + is_relative_to；文件名用 uuid 重命名；\n"
 "读文件改为按 ID 查数据库拿真实路径，彻底不接受路径参数。",
 "from pathlib import Path\nbase = Path('/data/files').resolve()\n"
 "p = (base / name).resolve()\nif not p.is_relative_to(base): abort(403)\nreturn p.read_bytes()",
 "python",
 "路径参数必须 resolve 后校验前缀，或改为 ID 映射。",
 "?file=../../../../etc/passwd\n?file=/etc/passwd\n?file=....//....//etc/passwd",
 "if ('..' in param or param.startswith('/')): block()", "", "", "../,/etc/passwd,%2e%2e",
 "resolve + 前缀校验；改用 ID 映射；WAF 拦截 ../ 与绝对路径。",
 ["%2e%2e%2f 编码", "....// 双写", "..%5c Windows 反斜杠", "绝对路径直接覆盖 base"],
 "误报：路径常量拼接不构成风险。",
 "lfi,path-traversal,python",
 ["https://cwe.mitre.org/data/definitions/22.html"] ))

T1.append(T(
 "Python SSRF（requests / urllib 无校验）", "ssrf", "python", "high",
 "requests.get(user_url) 未校验协议与目标，可打内网 169.254.169.254 元数据、Redis、"
 "FPM、K8s API，甚至 file:// 读本地文件；follow_redirects 会绕过一次性校验。",
 ["requests.get", "urllib.request.urlopen", "httpx", "aiohttp"],
 ["requests.get(", "urlopen(", "allow_redirects=True"],
 ["request.args", "request.json"],
 [R("kbpy-ssrf-1", "requests 使用用户 URL", "regex",
    r"requests\.(get|post|request)\s*\(\s*(url|request\.|.*request\.(args|form|json))", "high", 1,
    "requests 目标 URL 来自请求"),
  R("kbpy-ssrf-2", "urllib 打开用户输入", "regex", r"urlopen\s*\(\s*(request\.|url)", "high", 2,
    "urlopen 目标来自用户输入"),
  R("kbpy-ssrf-3", "重定向跟随", "regex", r"allow_redirects\s*=\s*True", "medium", 3,
    "跟随重定向可绕过域名白名单")],
 "只允许 http/https + 域名白名单，并 allow_redirects=False。",
 "解析 DNS 后校验 IP 不在私网/回环/链路本地段；禁用 file/gopher/dict 协议；\n"
 "出网走统一代理并做响应大小与超时限制。",
 "import ipaddress, socket, urllib.parse\nfrom urllib.parse import urlparse\nu = urlparse(url)\n"
 "if u.scheme not in ('http','https'): abort(400)\n"
 "if not u.hostname.endswith('.example.com'): abort(400)\n"
 "ip = ipaddress.ip_address(socket.gethostbyname(u.hostname))\n"
 "if ip.is_private or ip.is_loopback or ip.is_link_local: abort(400)",
 "python",
 "SSRF 必须协议 + 域名白名单 + DNS 解析后校验私网。",
 "?url=http://169.254.169.254/latest/meta-data/\n?url=file:///etc/passwd\n?url=gopher://127.0.0.1:6379/_INFO",
 "if (re.search(r'127\\.0\\.0\\.1|169\\.254|10\\.|192\\.168|file://|gopher://', url)): block()", "",
 "", "169.254.169.254,gopher://,file://",
 "协议白名单 + 私网 IP 校验 + 关闭重定向；WAF 拦截元数据地址。",
 ["302 跳转到内网", "DNS rebinding", "十进制/八进制 IP 1.0.0.127", "IPv6 [::1]", "短链接"],
 "误报：URL 完全由代码常量构造时无风险。",
 "ssrf,python,metadata",
 ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"] ))

T1.append(T(
 "Python SQL 注入（拼接 / text() / Raw）", "sqli", "python", "critical",
 "cursor.execute(f\"...{x}...\")、SQLAlchemy 的 text() 与 raw SQL 拼接、Django extra() 都会引入注入；"
 "ORM 过滤器传字符串也会被当作 SQL 片段。",
 ["cursor.execute", "text", "raw", "extra"],
 ["execute(", "text(", ".raw(", "extra("],
 ["request.args", "request.form"],
 [R("kbpy-sqli-1", "execute 字符串拼接", "regex",
    r"execute\s*\(\s*(f[\"']|\"[^\"']*\"\s*%|\"[^\"']*\"\s*\+|'[^']*'\s*%|'[^']*'\s*\+)", "critical", 1,
    "execute 参数为拼接字符串"),
  R("kbpy-sqli-2", "SQLAlchemy text 拼接", "regex", r"text\s*\(\s*(f[\"']|\"[^\"']*\"\s*\+)", "critical", 1,
    "text() 内拼接变量"),
  R("kbpy-sqli-3", "Django extra 使用输入", "regex", r"\.extra\s*\([^)]*(request\.|%s.*%|\\+)", "high", 2,
    "extra() 拼接 SQL 片段")],
 "cursor.execute(\"SELECT * FROM t WHERE id=%s\", (uid,))",
 "全部使用参数化查询；ORM 用 filter(id=uid)；禁止字符串拼接与 f-string 进 SQL。",
 "cur.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"
 "User.query.filter_by(id=uid).first()\n"
 "session.execute(text('SELECT * FROM users WHERE id=:id'), {'id': uid})",
 "python",
 "SQL 必须参数化绑定，f-string 拼接等于注入。",
 "?id=1 UNION SELECT username,password FROM users\n?id=1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)",
 "if (re.search(r'(union\\s+select|sleep\\(|benchmark\\(|information_schema)', q, re.I)): block()", "",
 "", "union select,sleep,information_schema",
 "参数化查询；WAF 拦截 UNION/SLEEP/注释符。",
 ["/**/ 注释替代空格", "大小写 UnIoN", "%55NION 编码", "盲注用 time-based"],
 "误报：execute 使用参数化占位符不构成风险。",
 "sqli,python,orm",
 ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"] ))

T1.append(T(
 "Python 弱密钥 / 硬编码凭据", "weak-crypto", "python", "high",
 "SECRET_KEY 硬编码或为空可伪造 Flask session；MD5/SHA1 存密码、random 生成令牌、"
 "DEBUG=True 暴露 Werkzeug 控制台（可 RCE）。",
 ["SECRET_KEY", "hashlib.md5", "random", "DEBUG"],
 ["SECRET_KEY", "app.run(debug=True)", "hashlib.md5("],
 ["config.py", ".env", "app.py"],
 [R("kbpy-key-1", "硬编码 SECRET_KEY", "regex",
    r"SECRET_KEY\s*=\s*['\"][^'\"]{1,32}['\"]", "high", 1, "SECRET_KEY 硬编码且长度偏短"),
  R("kbpy-key-2", "debug=True 上线", "regex", r"(app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)", "high", 2,
    "开启调试模式，Werkzeug 控制台可 RCE"),
  R("kbpy-key-3", "不安全哈希存密码", "regex", r"hashlib\.(md5|sha1)\s*\(", "medium", 2,
    "使用 MD5/SHA1 存储密码")],
 "SECRET_KEY=os.environ['SECRET_KEY']；debug=False。",
 "用 secrets.token_hex(32) 生成密钥并放环境变量；密码用 bcrypt/argon2；\n"
 "令牌用 secrets 模块而非 random。",
 "import os, secrets\napp.secret_key = os.environ['SECRET_KEY']\n"
 "from werkzeug.security import generate_password_hash, check_password_hash\n"
 "pw_hash = generate_password_hash(pw, method='argon2')",
 "python",
 "密钥进环境变量、密码用 argon2、关调试。",
 "flask-unsign --decode --cookie '<session>'\nflask-unsign --unsign --cookie '<session>' --wordlist rockyou.txt\n"
 "# 命中后可 --sign 伪造 admin session",
 "if (re.search(r\"SECRET_KEY\\s*=\\s*['\\\"]\", code)): warn()", "", "", "SECRET_KEY,debug=True,md5",
 "密钥外置并轮换；关闭 debug；密码哈希升级 argon2。",
 ["空 SECRET_KEY", "密钥为 'secret'/'changeme'", "同一密钥多环境复用"],
 "误报：测试配置文件中出现密钥需结合部署环境判断。",
 "weak-crypto,python,flask,secret",
 ["https://flask.palletsprojects.com/en/latest/config/"] ))

data = T1
p = os.path.join(OUT, "07-knowledge-php-py.json")
with open(p, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=1)
ids = [r["rule_id"] for t in data for r in t["match_rules"]]
print("templates:", len(data), "rules:", len(ids), "dup:", len(ids)-len(set(ids)))
print("wrote", p, os.path.getsize(p))
