#!/usr/bin/env python3
"""从 NVD API 2.0 采集 2020–2026 年的 CVE，生成「漏洞知识库」条目。

设计原则：
- 只写 NVD 上真实存在的编号与描述，绝不编造 CVE 号或利用细节；
- 中文部分只做「产品 + 漏洞类型 + 影响版本」的客观归纳，漏洞类型取自 CWE；
- exploit_tip / fix_* 用「按漏洞类型的通用打法」，不假称针对该 CVE 验证过；
- 每条都带 NVD 链接，方便逐条复核。

用法：
    python3 ext/tools/cve_harvest.py                 # 全量采集（约 10-20 分钟，NVD 限速 5 次/30 秒）
    python3 ext/tools/cve_harvest.py --resume        # 断点续跑（复用 .cache/nvd/*.json）
    python3 ext/tools/cve_harvest.py --max-per-kw 12 --cap 700
输出：
    ext/tools/awdp-lib-extra/11-cve-knowledge.json
"""

import argparse
import glob
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, ".cache", "nvd")
OUT = os.path.join(ROOT, "ext", "tools", "awdp-lib-extra", "11-cve-knowledge.json")
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "LingOps-AWDP-Content/1.0 (+https://github.com/GeWu-academy/LingOps-Enhanced)"

# 关键词 → (language, framework)。按 AWD / 常见靶场栈挑选。
KEYWORDS = {
    # ── PHP 生态 ────────────────────────────────────────────────
    "php": ("php", "PHP"),
    "thinkphp": ("php", "ThinkPHP"),
    "laravel": ("php", "Laravel"),
    "wordpress": ("php", "WordPress"),
    "drupal": ("php", "Drupal"),
    "joomla": ("php", "Joomla"),
    "dedecms": ("php", "DedeCMS"),
    "discuz": ("php", "Discuz!"),
    "phpcms": ("php", "PHPCMS"),
    "ecshop": ("php", "ECShop"),
    "yii": ("php", "Yii"),
    "symfony": ("php", "Symfony"),
    "codeigniter": ("php", "CodeIgniter"),
    "phpmyadmin": ("php", "phpMyAdmin"),
    "adminer": ("php", "Adminer"),
    "ueditor": ("php", "UEditor"),
    "kindeditor": ("php", "KindEditor"),
    # ── Java 生态 ───────────────────────────────────────────────
    "java": ("java", "Java"),
    "spring": ("java", "Spring"),
    "struts": ("java", "Struts2"),
    "shiro": ("java", "Apache Shiro"),
    "log4j": ("java", "Log4j"),
    "fastjson": ("java", "Fastjson"),
    "jackson": ("java", "Jackson"),
    "xstream": ("java", "XStream"),
    "snakeyaml": ("java", "SnakeYAML"),
    "weblogic": ("java", "WebLogic"),
    "tomcat": ("java", "Tomcat"),
    "jetty": ("java", "Jetty"),
    "jboss": ("java", "JBoss"),
    "activemq": ("java", "ActiveMQ"),
    "solr": ("java", "Apache Solr"),
    "ofbiz": ("java", "Apache OFBiz"),
    "h2 database": ("java", "H2 Database"),
    "mybatis": ("java", "MyBatis"),
    "nacos": ("java", "Nacos"),
    "rocketmq": ("java", "RocketMQ"),
    "zookeeper": ("java", "ZooKeeper"),
    "jenkins": ("java", "Jenkins"),
    "confluence": ("java", "Confluence"),
    "jira": ("java", "Jira"),
    "gitlab": ("ruby", "GitLab"),
    # ── Node / Python / Go ──────────────────────────────────────
    "node.js": ("nodejs", "Node.js"),
    "express": ("nodejs", "Express"),
    "lodash": ("nodejs", "lodash"),
    "jsonwebtoken": ("nodejs", "jsonwebtoken"),
    "mongoose": ("nodejs", "Mongoose"),
    "sequelize": ("nodejs", "Sequelize"),
    "next.js": ("nodejs", "Next.js"),
    "electron": ("nodejs", "Electron"),
    "django": ("python", "Django"),
    "flask": ("python", "Flask"),
    "jinja2": ("python", "Jinja2"),
    "celery": ("python", "Celery"),
    "pyyaml": ("python", "PyYAML"),
    "paramiko": ("python", "Paramiko"),
    "jupyter": ("python", "Jupyter"),
    "superset": ("python", "Superset"),
    "airflow": ("python", "Airflow"),
    "gradio": ("python", "Gradio"),
    "langflow": ("python", "Langflow"),
    "mlflow": ("python", "MLflow"),
    "ollama": ("python", "Ollama"),
    "pytorch": ("python", "PyTorch"),
    "golang": ("go", "Go"),
    "go-jose": ("go", "go-jose"),
    # ── 中间件 / 基础设施 ───────────────────────────────────────
    "nginx": ("mixed", "nginx"),
    "apache http server": ("mixed", "Apache HTTP Server"),
    "openssl": ("mixed", "OpenSSL"),
    "openssh": ("mixed", "OpenSSH"),
    "redis": ("mixed", "Redis"),
    "mysql": ("mixed", "MySQL"),
    "postgresql": ("mixed", "PostgreSQL"),
    "mongodb": ("mixed", "MongoDB"),
    "elasticsearch": ("mixed", "Elasticsearch"),
    "kibana": ("mixed", "Kibana"),
    "docker": ("mixed", "Docker"),
    "kubernetes": ("mixed", "Kubernetes"),
    "grafana": ("mixed", "Grafana"),
    "zabbix": ("mixed", "Zabbix"),
    "rabbitmq": ("mixed", "RabbitMQ"),
    "fortinet": ("mixed", "Fortinet"),
    "citrix": ("mixed", "Citrix"),
    "vmware": ("mixed", "VMware"),
    "ivanti": ("mixed", "Ivanti"),
    "exchange server": ("mixed", "Exchange Server"),
    "hikvision": ("mixed", "海康威视"),
    "dahua": ("mixed", "大华"),
    "totolink": ("mixed", "TOTOLINK"),
    "d-link": ("mixed", "D-Link"),
    "netgear": ("mixed", "NETGEAR"),
    "ruijie": ("mixed", "锐捷"),
    "seeyon": ("java", "致远 OA"),
    "weaver": ("java", "泛微 OA"),
    "tongda": ("php", "通达 OA"),
    "zentao": ("php", "禅道"),
    "yonyou": ("java", "用友"),
}

# CWE → (category, 中文类型名, 通用打法, 通用修复)
CWE_MAP = {
    "CWE-89": ("sqli", "SQL 注入",
               "先判注入点类型（数字/字符），再试联合、报错、布尔、时间盲注；有 WAF 时用等价替换、注释、编码绕过。",
               "全部改预编译参数化查询，禁止字符串拼接 SQL。"),
    "CWE-564": ("sqli", "SQL 注入（Hibernate HQL）",
                "HQL 拼接点可注入，注意 HQL 语法与原生 SQL 的差异。",
                "使用命名参数绑定，禁止拼接 HQL。"),
    "CWE-78": ("rce", "命令注入",
               "命令分隔符（; | || & && ` $() 换行）逐个试，注意过滤黑名单；无回显时用 DNS/HTTP 外带或时间盲注。",
               "改用参数数组调用，不经过 shell；对输入做白名单校验。"),
    "CWE-77": ("rce", "命令注入",
               "命令分隔符逐个试，无回显时用外带通道确认。",
               "禁止拼接命令字符串，使用安全 API 与白名单。"),
    "CWE-94": ("rce", "代码注入",
               "找可控的 eval / 表达式解析入口，先做无害探测（算术表达式）再升级为命令执行。",
               "禁止把外部输入交给 eval / 表达式引擎；确需动态执行时用白名单模板。"),
    "CWE-95": ("rce", "代码注入（eval）",
               "eval 类入口优先，注意先绕过滤再拼系统命令。",
               "移除 eval，改用受限解析器。"),
    "CWE-502": ("deserialization", "反序列化",
                "确认可控的序列化入口与链依赖，用 ysoserial / marshalsec 等生成对应 gadget；注意 JDK 版本与依赖。",
                "禁止反序列化不可信数据；必须时用白名单类过滤（ObjectInputFilter / ValidatingObjectInputStream）。"),
    "CWE-611": ("xxe", "XXE",
                "先试外部实体读文件，再试 OOB 外带与 SSRF 内网探测；注意是否只做了 DOCTYPE 黑名单。",
                "解析器禁用外部实体与 DTD（disallow-doctype-decl / FEATURE_SECURE_PROCESSING）。"),
    "CWE-827": ("xxe", "XXE",
                "试 DOCTYPE 外部实体，注意编码与嵌套绕过。",
                "禁用 DTD 与外部实体。"),
    "CWE-434": ("upload", "任意文件上传",
                "按扩展名 → Content-Type → 魔术字节 → 二次渲染的顺序逐层试，配合 .htaccess / .user.ini / 解析链落地。",
                "白名单扩展名 + 服务端重命名 + 上传目录禁执行 + 内容校验。"),
    "CWE-22": ("lfi", "路径穿越",
               "试 ../ 与其编码变体（%2e%2e%2f、..%2f、双重编码），Windows 下试 ..\\ 与 8.3 短名。",
               "规范化路径后校验前缀，禁止直接拼接用户输入。"),
    "CWE-23": ("lfi", "路径穿越",
               "试相对路径穿越与编码变体，注意是否只过滤了一次。",
               "规范化 + 白名单目录校验。"),
    "CWE-36": ("lfi", "绝对路径穿越",
               "直接试绝对路径读取敏感文件。",
               "禁止用户输入决定文件路径。"),
    "CWE-73": ("file-write", "任意文件写入",
               "找可控路径的写文件点，写 webshell 或覆盖配置；注意写权限与落地目录是否可访问。",
               "路径白名单 + 固定文件名 + 禁止写入可执行目录。"),
    "CWE-918": ("ssrf", "SSRF",
               "先试内网地址与云元数据（169.254.169.254），再试协议走私（gopher / dict / file）打内网服务。",
               "协议与目标地址双白名单，禁止跟随重定向，出网走代理。"),
    "CWE-943": ("nosqli", "NoSQL 注入",
               "试 $ne / $gt / $regex / $where 操作符注入，注意 JSON 与表单两种传参形态。",
               "对操作符键做白名单过滤，禁用 $where。"),
    # ── 2026-11 补：按 NVD 缓存里出现频率最高的未映射 CWE 增补 ──
    "CWE-20": ("info-leak", "输入校验不当",
               "先找所有直接透传请求参数的入口，逐步试注入/穿越/越权，注意是否只在前端校验。",
               "服务端统一校验：类型、长度、字符集、范围，拒绝而非过滤。"),
    "CWE-74": ("rce", "特殊元素注入",
               "按注入点上下文（SQL/命令/模板/表达式）分别试对应 payload，注意多重编码。",
               "按上下文做输出编码与参数化，禁止字符串拼接。"),
    "CWE-75": ("rce", "特殊元素注入（多层）",
               "试多重编码与二次解析绕过。",
               "解码后统一校验，避免二次解析。"),
    "CWE-88": ("rce", "参数注入",
               "试在参数值里插入空格与 -flag 形式改变程序行为。",
               "参数与值分离传递，不拼接命令行字符串。"),
    "CWE-1336": ("ssti", "服务端模板注入",
               "先试 ${7*7} / {{7*7}} 探测，再按引擎（Freemarker/Velocity/Jinja2/Twig）升级到命令执行。",
               "模板源不可由用户输入拼接；沙箱化模板引擎。"),
    "CWE-917": ("ssti", "表达式语言注入",
               "试 OGNL/SpEL/EL 表达式，先算术探测再执行命令。",
               "禁止对外部输入求值表达式。"),
    "CWE-639": ("auth-bypass", "越权（IDOR）",
               "抓包替换对象 ID（自增/用户名/UUID），看服务端是否校验归属。",
               "每个对象访问都校验 owner 与当前会话的关系。"),
    "CWE-284": ("auth-bypass", "访问控制不当",
               "枚举同级接口与不同角色，找未做权限判定的端点。",
               "统一鉴权中间件 + 默认拒绝。"),
    "CWE-285": ("auth-bypass", "授权不当",
               "用低权限账号访问高权限接口，注意参数里可传 role/tenant。",
               "服务端按会话身份判定权限，忽略客户端传的权限字段。"),
    "CWE-269": ("auth-bypass", "权限管理不当",
               "找可自提权的接口（改角色、改归属、邀请成员）。",
               "权限变更走独立审批接口并校验操作者权限。"),
    "CWE-276": ("auth-bypass", "默认权限过宽",
               "检查默认账号/默认角色是否带管理权限。",
               "默认最小权限；首次登录强制改密。"),
    "CWE-732": ("auth-bypass", "关键资源权限过宽",
               "检查上传目录、配置文件、备份目录的可访问性。",
               "按最小权限设置文件与目录权限。"),
    "CWE-290": ("auth-bypass", "认证绕过（伪造身份）",
               "试伪造 Cookie/Header/源 IP 绕过白名单。",
               "不要基于可伪造的客户端字段做认证。"),
    "CWE-295": ("weak-crypto", "证书校验不当",
               "中间人抓包看客户端是否校验证书。",
               "启用完整证书链与主机名校验，禁止 trustAll。"),
    "CWE-209": ("info-leak", "报错信息泄露",
               "触发异常看是否回显堆栈、SQL、路径。",
               "统一错误页，日志落服务端不外泄。"),
    "CWE-312": ("info-leak", "敏感信息明文存储",
               "找配置/日志/备份里的口令与密钥。",
               "敏感字段加密存储，日志脱敏。"),
    "CWE-522": ("weak-crypto", "凭据保护不足",
               "抓取传输与存储中的凭据，试离线破解。",
               "口令用 bcrypt/argon2 存储，传输强制 TLS。"),
    "CWE-119": ("rce", "内存缓冲区错误",
               "针对设备/服务端二进制，定位解析入口后做溢出或越界读写，配合 ROP。",
               "升级到修复版本；启用 ASLR/DEP/栈保护。"),
    "CWE-121": ("rce", "栈溢出",
               "定位栈上拷贝点（strcpy/sprintf），构造超长输入覆盖返回地址。",
               "使用安全字符串函数并做长度校验。"),
    "CWE-122": ("rce", "堆溢出",
               "定位堆分配与拷贝长度不一致处，构造越界写。",
               "严格校验长度，使用安全分配封装。"),
    "CWE-125": ("info-leak", "越界读取",
               "构造超长/畸形输入读取相邻内存，泄露地址或密钥。",
               "严格边界检查。"),
    "CWE-1321": ("prototype-pollution", "原型污染",
                 "找递归 merge / set 类入口，注入 __proto__ / constructor.prototype，再找触发 gadget（模板渲染、child_process）。",
                 "merge 前过滤 __proto__ / prototype / constructor 键，或用 Object.create(null)。"),
    "CWE-287": ("auth-bypass", "认证绕过",
                "看鉴权是否只在网关层、是否可路径穿越或后缀绕过（.do/.js/;.css），再试默认口令与 JWT 篡改。",
                "鉴权在业务层统一拦截，不做后缀/路径特判。"),
    "CWE-288": ("auth-bypass", "认证绕过（备用通道）",
                "找未受保护的同功能接口或调试入口。",
                "统一鉴权中间件，收敛内部接口。"),
    "CWE-306": ("auth-bypass", "缺失认证",
                "直接访问敏感接口看是否免登录。",
                "所有敏感接口强制鉴权。"),
    "CWE-862": ("auth-bypass", "缺失授权",
                "换低权限账号重放同一请求，看是否只校验登录不校验权限。",
                "服务端逐对象鉴权（避免 IDOR）。"),
    "CWE-863": ("auth-bypass", "授权错误",
                "尝试越权访问他人对象与管理员接口。",
                "以会话身份为准做对象级鉴权。"),
    "CWE-347": ("jwt", "签名校验缺陷",
                "试 alg=none、RS256→HS256 算法混淆、弱密钥爆破、jwk 注入。",
                "固定算法白名单，校验签名与声明，密钥足够强。"),
    "CWE-798": ("weak-crypto", "硬编码凭据",
                "在源码/镜像里搜默认口令与密钥，直接登录。",
                "移除硬编码凭据，改用密钥管理服务。"),
    "CWE-259": ("weak-crypto", "硬编码口令",
                "用默认口令直接登录。",
                "首次启动强制改密。"),
    "CWE-521": ("weak-crypto", "弱口令策略",
                "对登录口做小字典喷洒（注意锁定阈值）。",
                "强制口令复杂度与失败锁定。"),
    "CWE-326": ("weak-crypto", "加密强度不足",
                "离线爆破弱加密数据。",
                "使用足够强度的现代算法与密钥长度。"),
    "CWE-327": ("weak-crypto", "使用了不安全算法",
                "识别 MD5/SHA1/DES/ECB 等，做碰撞或离线爆破。",
                "替换为 AES-GCM / SHA-256 及以上。"),
    "CWE-352": ("csrf", "CSRF",
                "构造跨站表单/请求，观察是否校验 token 与 Referer。",
                "加 CSRF token 或 SameSite Cookie。"),
    "CWE-601": ("open-redirect", "开放重定向",
                "试 //evil.com、https:evil.com、@evil.com 等变体。",
                "重定向目标做域名白名单。"),
    "CWE-90": ("ldap", "LDAP 注入",
                "在搜索过滤器里注入 *)(uid=* 之类的通配与逻辑符。",
                "对过滤器特殊字符做转义。"),
    "CWE-643": ("xpath", "XPath 注入",
                "在 XPath 查询点注入 ' or '1'='1 之类条件。",
                "参数化或严格转义。"),
    "CWE-113": ("crlf", "CRLF 注入",
                "在回显到响应头的参数里注入 %0d%0a 造响应拆分。",
                "输出到响应头前过滤 CR/LF。"),
    "CWE-444": ("request-smuggling", "HTTP 请求走私",
                "构造 CL.TE / TE.CL 差异请求，观察前后端解析不一致。",
                "统一前后端解析规则，禁用歧义头。"),
    "CWE-362": ("race-condition", "条件竞争",
                "并发打同一资源（上传/兑换/改名），观察是否绕过检查。",
                "关键操作用锁或原子操作。"),
    "CWE-79": ("xss", "XSS",
               "按上下文选 payload（HTML/属性/JS/URL），注意过滤与编码差异。",
               "按输出上下文编码，配合 CSP。"),
    "CWE-200": ("info-leak", "信息泄露",
                "从报错、备份、调试端点、`.git`/`.env` 里捞凭据与路径。",
                "关闭调试与目录列表，移除备份文件。"),
    "CWE-538": ("info-leak", "敏感文件暴露",
                "扫常见备份/配置文件后缀与源码目录。",
                "禁止把敏感文件放在 Web 根目录。"),
    "CWE-668": ("info-leak", "资源暴露",
                "探测未授权可访问的内部端点。",
                "收敛暴露面并加鉴权。"),
    "CWE-532": ("info-leak", "日志泄露敏感信息",
                "从日志与报错里提取凭据。",
                "日志脱敏。"),
    "CWE-120": ("rce", "缓冲区溢出",
               "按协议构造超长字段触发崩溃，再考虑 ROP；AWD 里更多用于打服务端守护进程。",
               "升级到修复版本，开启编译期保护。"),
    "CWE-787": ("rce", "越界写",
                "构造畸形输入触发越界，评估是否可控。",
                "升级修复版本。"),
    "CWE-416": ("rce", "释放后重用",
                "构造生命周期错配的输入序列。",
                "升级修复版本。"),
    "CWE-190": ("rce", "整数溢出",
                "构造边界值输入。",
                "升级修复版本。"),
}

# 关键词命中时给 description 用的产品名（CPE 里 vendor:product 不可读时兜底）
GENERIC_TIP = ("先确认目标版本落在受影响区间（NVD 参考链接里有版本范围），再按漏洞类型选打法；"
               "AWD 里优先找不需要交互、能直接拿权限的路径。")

MANIFEST = {  # ecosystem → (文件名, 版本片段正则片段)
    "maven": ("pom.xml", r"<version>"),
    "npm": ("package.json", r"\"version\"\s*:\s*\""),
    "pypi": ("requirements.txt", r""),
    "go": ("go.mod", r""),
    "composer": ("composer.json", r"\"version\"\s*:\s*\""),
}


def fetch(keyword, start_index=0, per_page=300, retries=4):
    """拉一页 NVD 结果。

    注意：NVD API 2.0 在本机实测带 pubStartDate/pubEndDate 会 404，
    所以时间范围只能在客户端按 CVE 编号里的年份过滤。
    不带 cvssV3Severity（会多一倍请求），严重度也在客户端筛。
    """
    os.makedirs(CACHE, exist_ok=True)
    tag = re.sub(r"[^a-z0-9]+", "-", keyword.lower()).strip("-")
    path = os.path.join(CACHE, "%s-%d-%d.json" % (tag, start_index, per_page))
    if os.path.isfile(path) and os.path.getsize(path) > 100:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(per_page),
        "startIndex": str(start_index),
    }
    url = API + "?" + urllib.parse.urlencode(params)
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode("utf-8"))
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
            return data
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                time.sleep(20 * (attempt + 1))
                continue
            print("  ! %s@%d HTTP %s" % (keyword, start_index, e.code))
            return {"vulnerabilities": [], "totalResults": 0}
        except Exception as e:  # 网络抖动
            print("  ! %s@%d %s" % (keyword, start_index, e))
            time.sleep(10 * (attempt + 1))
    return {"vulnerabilities": [], "totalResults": 0}


# 纯 DoS / 资源耗尽类，AWD 场景没有利用价值，直接丢弃避免污染分类
CWE_DROP = {"CWE-400", "CWE-674", "CWE-770", "CWE-476", "CWE-617", "CWE-835", "CWE-1333",
            "CWE-776", "CWE-1021"}

# 这些类型在 AWD 里 medium 也值得收（XSS/SSRF/XXE/上传/SSTI/反序列化/注入）
CWE_MEDIUM_OK = {"CWE-79", "CWE-80", "CWE-83", "CWE-918", "CWE-611", "CWE-827", "CWE-434",
                 "CWE-1336", "CWE-917", "CWE-502", "CWE-89", "CWE-78", "CWE-94", "CWE-22",
                 "CWE-352", "CWE-601", "CWE-113", "CWE-943", "CWE-1321", "CWE-639"}


def cvss_of(cve):
    m = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for entry in m.get(key) or []:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            sev = (data.get("baseSeverity") or entry.get("baseSeverity") or "").lower()
            if score is not None:
                return float(score), sev
    return 0.0, ""


def cwes_of(cve):
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value") or ""
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def products_of(cve):
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                crit = cm.get("criteria") or ""
                parts = crit.split(":")
                if len(parts) > 4:
                    vp = "%s %s" % (parts[3].replace("_", " "), parts[4].replace("_", " "))
                    vp = vp.strip()
                    if vp and vp not in out:
                        out.append(vp)
    return out


def versions_of(cve, limit=4):
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                if not cm.get("vulnerable"):
                    continue
                lo, hi = cm.get("versionStartIncluding"), cm.get("versionEndExcluding")
                exact = (cm.get("criteria") or "").split(":")[5] if len((cm.get("criteria") or "").split(":")) > 5 else ""
                if lo and hi:
                    s = ">=%s, <%s" % (lo, hi)
                elif hi:
                    s = "<%s" % hi
                elif lo:
                    s = ">=%s" % lo
                elif exact and exact not in ("*", "-"):
                    s = exact
                else:
                    continue
                if s not in out:
                    out.append(s)
    return out[:limit]


SCORE = {}


def build_entry(cve, keyword, lang, framework, max_refs=3):
    cid = cve["id"]
    year = int(cid.split("-")[1])
    desc = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "").strip()
    score, sev = cvss_of(cve)
    cwes = cwes_of(cve)
    cat, cat_cn, tip, fix = ("info-leak", "安全问题", GENERIC_TIP, "升级到厂商修复版本。")
    for c in cwes:
        if c in CWE_MAP:
            cat, cat_cn, tip, fix = CWE_MAP[c]
            break
    prods = products_of(cve)
    prod = prods[0] if prods else framework
    vers = versions_of(cve)
    if sev not in ("critical", "high", "medium", "low"):
        sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    name = "%s %s %s" % (cid, prod, cat_cn)
    ver_txt = ("；影响版本 " + "、".join(vers)) if vers else ""
    if len(desc) > 600:
        desc = desc[:600].rsplit(" ", 1)[0] + " …"
    description = "%s 存在%s%s。NVD 摘要：%s" % (prod, cat_cn, ver_txt, desc)
    SCORE[cid] = score
    refs = ["https://nvd.nist.gov/vuln/detail/" + cid]
    for r in (cve.get("references") or [])[:max_refs]:
        u = r.get("url")
        if u and u not in refs:
            refs.append(u)
    return {
        "name": name,
        "category": cat,
        "language": lang,
        "framework": framework,
        "severity": sev,
        "description": description,
        "danger_functions": [],
        "code_patterns": [],
        "input_sources": [],
        "match_rules": [],
        "fix_fast_method": fix,
        "fix_secure_method": fix,
        "fix_code_example": "",
        "fix_code_language": "",
        "fix_summary": "升级到厂商修复版本，并按「%s」的通用做法加固。" % cat_cn,
        "exploit_tip": tip,
        "waf_template": "",
        "waf_dependencies": "",
        "whitelist_rule": "",
        "blacklist_rule": "",
        "framework_fix": "",
        "bypass_methods": [],
        "false_positive": "",
        "tags": ["cve", str(year), prod.lower(), cat],
        "references": refs,
        "source_type": "cve-nvd",
        "is_active": 1,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true", help="复用缓存，不重新请求 NVD")
    ap.add_argument("--max-per-kw", type=int, default=14, help="每个关键词最多收多少条（按 CVSS 降序）")
    ap.add_argument("--per-page", type=int, default=300, help="NVD 每页条数")
    ap.add_argument("--cap", type=int, default=700, help="总条数上限")
    ap.add_argument("--year-from", type=int, default=2020)
    ap.add_argument("--year-to", type=int, default=2026)
    args = ap.parse_args()

    if not args.resume and os.path.isdir(CACHE):
        for p in glob.glob(os.path.join(CACHE, "*.json")):
            os.remove(p)

    seen = {}
    kw_order = list(KEYWORDS.items())
    for i, (kw, (lang, framework)) in enumerate(kw_order, 1):
        bucket = []
        per_page = args.per_page
        pages = [0]
        first = fetch(kw, 0, per_page)
        if not args.resume:
            time.sleep(6.2)
        total = int(first.get("totalResults") or 0)
        # NVD 默认按发布时间倒序，只取首页会全是最近两年；
        # 再跳一页到中段，保证 2020-2023 也有覆盖。
        if total > per_page * 3:
            pages.append(min(per_page * 2, total - 1))
        datas = [first]
        for idx in pages[1:]:
            datas.append(fetch(kw, idx, per_page))
            if not args.resume:
                time.sleep(6.2)
        got = 0
        for data in datas:
            vulns = data.get("vulnerabilities") or []
            got += len(vulns)
            for v in vulns:
                cve = v.get("cve") or {}
                cid = cve.get("id") or ""
                if not cid.startswith("CVE-"):
                    continue
                try:
                    year = int(cid.split("-")[1])
                except (IndexError, ValueError):
                    continue
                if not (args.year_from <= year <= args.year_to):
                    continue
                score, sev = cvss_of(cve)
                ws = cwes_of(cve)
                if ws and all(w in CWE_DROP for w in ws):
                    continue
                floor = 6.0 if any(w in CWE_MEDIUM_OK for w in ws) else 7.0
                if sev not in ("critical", "high") and score < floor:
                    continue
                bucket.append(cve)
        print("[%2d/%d] %-22s total=%-6d 取回 %4d 条" % (i, len(kw_order), kw, total, got))
        # 同关键词内按 CVSS 降序，但每个 category 最多取 4 条，
        # 否则高分的 RCE/SQLi 会把 XSS/SSRF/上传全挤掉。
        bucket.sort(key=lambda c: (-cvss_of(c)[0], c["id"]))
        per_cat, picked = {}, 0
        for cve in bucket:
            if cve["id"] in seen:
                continue
            entry = build_entry(cve, kw, lang, framework)
            cat = entry["category"]
            if per_cat.get(cat, 0) >= 4:
                continue
            per_cat[cat] = per_cat.get(cat, 0) + 1
            seen[cve["id"]] = entry
            picked += 1
            if picked >= args.max_per_kw:
                break

    entries = list(seen.values())
    # 单类型占比上限 18%，避免 info-leak 这类泛化条目淹没整个知识库
    cat_cap = max(40, int(args.cap * 0.18))
    by_cat = {}
    kept = []
    entries.sort(key=lambda e: (-SCORE.get(e["name"].split(" ")[0], 0), e["name"]))
    for e in entries:
        c = e["category"]
        if by_cat.get(c, 0) >= cat_cap:
            continue
        by_cat[c] = by_cat.get(c, 0) + 1
        kept.append(e)
        if len(kept) >= args.cap:
            break
    entries = sorted(kept, key=lambda e: (e["category"], e["name"]))

    # 名称唯一性兜底
    used = set()
    for e in entries:
        base = e["name"]
        n = 2
        while e["name"] in used:
            e["name"] = "%s (%d)" % (base, n)
            n += 1
        used.add(e["name"])

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"knowledge": entries}, f, ensure_ascii=False, indent=2)
    print("\n写入 %s：%d 条" % (OUT, len(entries)))
    by_cat = {}
    for e in entries:
        by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
    print("按类型：", json.dumps(by_cat, ensure_ascii=False))
    by_year = {}
    for e in entries:
        y = e["name"].split("-")[1]
        by_year[y] = by_year.get(y, 0) + 1
    print("按年份：", json.dumps(by_year, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
