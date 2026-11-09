#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 2020-2026 CVE 家族扫描规则（12-rules-cve.json）。

设计原则：
1. 每条规则的 pattern 必须是 Go RE2 可编译的（无 lookahead / backreference）。
2. 规则只做"特征命中"，不做"漏洞判定"——description 里统一写明需人工确认，
   避免把"版本低于修复版"直接当成"一定存在漏洞"。
3. CVE 编号只写确有把握的；不确定的一律不写编号，只描述家族特征。
4. 生成时与 DB 现有 pattern 去重，重复的自动跳过并打印。

用法：
    python3 ext/tools/awdp-lib-gen/gen5_cve_rules.py            # 生成 JSON
    python3 ext/tools/awdp-lib-gen/gen5_cve_rules.py --stats    # 只统计
"""
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT = os.path.join(ROOT, "ext", "tools", "awdp-lib-extra", "12-rules-cve.json")
DB = os.path.join(ROOT, "data", "lingops.db")


def R(rule_id, name, lang, cat, sev, pattern, desc, fix, fw="", conf="medium", prio=2):
    return {
        "rule_id": rule_id,
        "name": name,
        "language": lang,
        "framework": fw,
        "category": cat,
        "severity": sev,
        "confidence": conf,
        "description": desc,
        "type": "regex",
        "pattern": pattern,
        "exclude_pattern": "",
        "priority": prio,
        "fix_suggestion": fix,
        "template_id": 0,
        "is_builtin": 1,
        "is_active": 1,
    }


RULES = []


def add(*args, **kw):
    RULES.append(R(*args, **kw))


# ============================================================
# 一、Java 生态：依赖版本 + 代码特征
# ============================================================
add("x3-java-log4j-version", "log4j-core 2.0~2.14 受影响版本", "java", "rce", "critical",
    r"log4j-core[\s\S]{0,300}?<version>\s*2\.(?:0|1[0-4])[.\d]*\s*<",
    "pom.xml 中 log4j-core 版本低于 2.15.0，存在 Log4Shell（CVE-2021-44228）风险。需人工确认实际加载版本。",
    "升级到 log4j-core 2.17.1+；临时缓解：-Dlog4j2.formatMsgNoLookups=true 并移除 JndiLookup.class",
    fw="log4j")
add("x3-java-jndi-lookup", "JNDI lookup 拼接外部输入", "java", "rce", "critical",
    r"(?:InitialContext|ctx|context)\s*\.\s*lookup\s*\(\s*[^)]{0,80}?(?:getParameter|getHeader|\+\s*\w+|String\.format)",
    "JNDI lookup 的 key 由请求参数或字符串拼接构成，攻击者可指向恶意 LDAP/RMI 服务实现远程类加载（Log4Shell / JNDI 注入家族）。",
    "禁止 lookup 使用外部可控字符串；升级 log4j 至 2.17.1+，限制出站 LDAP/RMI",
    fw="log4j", conf="high", prio=1)
add("x3-java-fastjson-autotype", "fastjson 开启 AutoType", "java", "deserialization", "critical",
    r"(?:setAutoTypeSupport\s*\(\s*true|autoTypeSupport\s*=\s*true|Feature\.SupportAutoType)",
    "fastjson 显式开启 AutoType，配合 parseObject 可触发 JNDI 注入链（CVE-2022-25845 等 fastjson 反序列化家族）。",
    "升级 fastjson 至 1.2.83+ 或迁移 fastjson2；关闭 AutoType 并启用 safeMode",
    fw="fastjson", conf="high", prio=1)
add("x3-java-fastjson-version", "fastjson 低于 1.2.83", "java", "deserialization", "high",
    r"<artifactId>\s*fastjson\s*</artifactId>[\s\S]{0,200}?<version>\s*1\.2\.(?:[0-7]?\d|8[0-2])\s*<",
    "fastjson 版本低于 1.2.83，历史 AutoType 绕过链较多（CVE-2022-25845 等）。需确认实际依赖版本。",
    "升级 fastjson 至 1.2.83+，或迁移 fastjson2 并开启 safeMode",
    fw="fastjson")
add("x3-java-xstream-version", "XStream 低于 1.4.18", "java", "deserialization", "high",
    r"<artifactId>\s*xstream\s*</artifactId>[\s\S]{0,200}?<version>\s*1\.4\.(?:[0-9]|1[0-7])\s*<",
    "XStream 版本低于 1.4.18，存在多条反序列化 gadget 绕过（CVE-2021-39139~39153 家族）。",
    "升级 XStream 至 1.4.20+，并使用白名单 allowTypes",
    fw="xstream")
add("x3-java-snakeyaml-version", "SnakeYAML 低于 2.0 未限制 Tag", "java", "deserialization", "high",
    r"<artifactId>\s*snakeyaml\s*</artifactId>[\s\S]{0,200}?<version>\s*1\.(?:[0-9]|[12]\d|3[01])\s*<",
    "SnakeYAML 1.x 默认允许全局 Tag，配合 new Yaml().load() 可实例化任意类（CVE-2022-1471）。",
    "升级 SnakeYAML 至 2.0+，或使用 SafeConstructor",
    fw="snakeyaml")
add("x3-java-shiro-version", "Shiro 低于 1.8.0", "java", "auth-bypass", "critical",
    r"<artifactId>\s*shiro-(?:core|web|spring)\s*</artifactId>[\s\S]{0,200}?<version>\s*1\.[0-7][.\d]*\s*<",
    "Shiro 版本低于 1.8.0，存在 rememberMe 反序列化（CVE-2016-4437）与路径鉴权绕过（CVE-2020-1957 / CVE-2020-11989 / CVE-2020-13933 / CVE-2021-41303 家族）。",
    "升级 Shiro 至 1.13.0+ 或 2.x；为 rememberMe Cookie 配置独立 AES key",
    fw="shiro", conf="high", prio=1)
add("x3-java-shiro-pathbypass", "Shiro 路径鉴权绕过特征", "java", "auth-bypass", "high",
    r"(?:shiroFilter|ShiroFilterFactoryBean)[\s\S]{0,400}?(?:/;\w+|/\*|/\*\*|\.\./|%2e%2e)",
    "Shiro 过滤器链配置中出现分号、通配符或编码路径，可能被用于绕过鉴权（CVE-2020-1957 / CVE-2021-41303 等家族）。需实测确认。",
    "升级 Shiro 至 1.13+；统一在网关层做路径规范化后再鉴权",
    fw="shiro")
add("x3-java-struts-version", "Struts2 低于 2.5.30", "java", "rce", "critical",
    r"<artifactId>\s*struts2-(?:core|convention)\s*</artifactId>[\s\S]{0,200}?<version>\s*2\.[0-5]\.[0-2]?\d\s*<",
    "Struts2 版本低于 2.5.30，存在 OGNL 注入家族风险（CVE-2020-17530 / CVE-2021-31805 / CVE-2023-50164 等）。",
    "升级 Struts2 至 6.3.0.1+ 或 2.5.33+；禁用通配符方法映射",
    fw="struts2", conf="high", prio=1)
add("x3-java-struts-ognl", "Struts2 OGNL 直接求值外部参数", "java", "rce", "critical",
    r"(?:Ognl\.(?:getValue|setValue|parseExpression)\s*\(|%\{\s*#(?:request|parameters|attr))",
    "代码中直接对请求参数做 OGNL 求值，可构造 OGNL 表达式执行任意代码（Struts2 S2 系列漏洞的根因模式）。",
    "禁止 OGNL 求值外部输入；升级 Struts2 并开启 strict-method-invocation",
    fw="struts2", conf="high", prio=1)
add("x3-java-spring4shell", "Spring4Shell 数据绑定特征", "java", "rce", "critical",
    r"(?:WebDataBinder|@InitBinder|setDisallowedFields)[\s\S]{0,200}?class\.(?:module\.classLoader|classLoader)",
    "Spring 参数绑定未禁用 class.* 属性，存在 Spring4Shell（CVE-2022-22965）风险。需确认 Spring 版本与部署方式（Tomcat WAR）。",
    "升级 Spring Framework 至 5.3.18+ / 5.2.20+；@InitBinder 中 setDisallowedFields(\"class.*\")",
    fw="spring", conf="medium", prio=1)
add("x3-java-spring-core-version", "spring-core 低于 5.3.18", "java", "rce", "high",
    r"<artifactId>\s*spring-(?:core|beans|webmvc)\s*</artifactId>[\s\S]{0,200}?<version>\s*5\.[0-3]\.(?:[0-9]|1[0-7])\s*<",
    "Spring Framework 版本低于 5.3.18，存在 Spring4Shell（CVE-2022-22965）与 CVE-2023-20863 等风险。",
    "升级 Spring Framework 至 6.0.8+ / 5.3.27+",
    fw="spring")
add("x3-java-spring-gateway-spel", "Spring Cloud Gateway SpEL 注入", "java", "rce", "critical",
    r"(?:ShortcutConfigurable|SpelExpressionParser|GatewayFilter)[\s\S]{0,300}?(?:getValue\(|addGatewayFilter)",
    "Spring Cloud Gateway 的 ShortcutConfigurable 对 filter 参数做 SpEL 求值，若 actuator 端点暴露且可写路由则可 RCE（CVE-2022-22947）。",
    "升级 Spring Cloud Gateway 至 3.1.1+ / 3.0.7+；关闭 /actuator/gateway 写端点",
    fw="spring", conf="medium", prio=1)
add("x3-java-jackson-version", "jackson-databind 低于 2.13.4", "java", "deserialization", "high",
    r"<artifactId>\s*jackson-databind\s*</artifactId>[\s\S]{0,200}?<version>\s*2\.(?:[0-9]|1[0-3])\.[0-3]?\d\s*<",
    "jackson-databind 版本偏低，历史黑名单绕过链较多。需确认是否开启 enableDefaultTyping。",
    "升级 jackson-databind 至 2.15+；禁用 enableDefaultTyping，使用 @JsonTypeInfo 白名单",
    fw="jackson")
add("x3-java-jackson-defaulttyping", "Jackson 开启 DefaultTyping", "java", "deserialization", "critical",
    r"(?:enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|@JsonTypeInfo\s*\(\s*use\s*=\s*Id\.CLASS)",
    "Jackson 开启多态反序列化，可被 gadget 链利用实现 RCE（jackson-databind 黑名单绕过家族）。",
    "改用 activateDefaultTyping 并配置 PolymorphicTypeValidator 白名单",
    fw="jackson", conf="high", prio=1)
add("x3-java-commonscollections", "commons-collections 3.2.1 gadget", "java", "deserialization", "high",
    r"<artifactId>\s*commons-collections\s*</artifactId>[\s\S]{0,200}?<version>\s*3\.2\.1\s*<",
    "commons-collections 3.2.1 是经典 Java 反序列化 gadget 依赖，配合任意 readObject 入口即可 RCE。",
    "升级至 commons-collections 3.2.2（限制 InvokerTransformer）或 4.4（SerializationUtils 校验）",
    fw="commons-collections")
add("x3-java-weblogic-console", "WebLogic 控制台/IIOP 暴露特征", "java", "rce", "critical",
    r"(?:/console/login/LoginForm\.jsp|/wls-wsat/|/bea_wls_internal/|/_async/|/uddiexplorer/)",
    "应用配置或源码中引用了 WebLogic 控制台与 wls-wsat 组件路径，历史反序列化漏洞密集（CVE-2020-14882 / CVE-2020-14883 / CVE-2023-21839 家族）。",
    "限制 /console 与 /wls-wsat 外网访问；升级 WebLogic 至最新 CPU 补丁",
    fw="weblogic", conf="high", prio=1)
add("x3-java-activemq-version", "ActiveMQ 低于 5.16.5 / 5.17.6", "java", "rce", "critical",
    r"<artifactId>\s*activemq-(?:broker|client|openwire)\s*</artifactId>[\s\S]{0,200}?<version>\s*5\.(?:1[0-6]\.[0-4]|17\.[0-5])\s*<",
    "ActiveMQ 版本低于修复版，OpenWire 反序列化可 RCE（CVE-2023-46604）。",
    "升级 ActiveMQ 至 5.18.3+ / 5.17.6+ / 5.16.7+；禁止 61616 端口外网暴露",
    fw="activemq", conf="high", prio=1)
add("x3-java-h2-console", "H2 Console 未禁用", "java", "rce", "high",
    r"(?:spring\.h2\.console\.enabled\s*=\s*true|/h2-console|org\.h2\.tools\.server\.WebServlet)",
    "H2 Console 暴露且允许 JNDI 数据源配置，可 RCE（CVE-2021-42392 / CVE-2022-23221）。",
    "生产环境关闭 spring.h2.console.enabled；升级 H2 至 2.2.220+",
    fw="h2")
add("x3-java-nacos-authbypass", "Nacos 默认 token / 鉴权绕过", "java", "auth-bypass", "critical",
    r"(?:nacos\.core\.auth\.enabled\s*=\s*false|nacos\.core\.auth\.server\.identity\.key\s*=\s*(?:secret|SecretKey012345678901234567890123456789012345678901234567890123456789)?)",
    "Nacos 关闭鉴权或使用默认 identity key，可未授权创建用户并利用 Derby 注入 RCE（CVE-2021-29441 / CVE-2021-29442 家族）。",
    "开启 nacos.core.auth.enabled 并设置强随机 identity key；升级 Nacos 至 2.2.1+",
    fw="nacos", conf="high", prio=1)
add("x3-java-rocketmq-broker", "RocketMQ Broker 未授权", "java", "rce", "high",
    r"(?:rocketmq\.brokerIP1|/namesrv/|brokerConfig\.setBrokerIP)",
    "配置中出现 RocketMQ Broker 对外地址，10911 端口未鉴权时存在 CVE-2023-33246 命令执行风险。",
    "升级 RocketMQ 至 5.1.1+ / 4.9.6+；Broker 端口仅内网可达",
    fw="rocketmq")
add("x3-java-tomcat-ajp", "Tomcat AJP 连接器暴露", "java", "lfi", "high",
    r"(?:protocol\s*=\s*[\"']AJP/1\.3[\"']|8009)",
    "启用 AJP 连接器（8009），存在 Ghostcat（CVE-2020-1938）任意文件读取风险。",
    "升级 Tomcat 至 9.0.31+ / 8.5.51+；注释 AJP Connector 或设置 secretRequired",
    fw="tomcat")
add("x3-java-jenkins-script", "Jenkins Script Console 暴露", "java", "rce", "critical",
    r"(?:/scriptText|/script\b|jenkins\.model\.Jenkins)",
    "引用 Jenkins Script Console 端点，未授权或弱口令时可 Groovy 任意代码执行。",
    "关闭匿名读权限；限制 /script 路径访问来源",
    fw="jenkins", conf="medium")
add("x3-java-solr-admin", "Solr Admin 未授权", "java", "rce", "critical",
    r"(?:/solr/admin/cores|/solr/[^/\"']+/config|params\.resource\.loader)",
    "Solr Admin API 可写配置，历史存在 Velocity 模板 RCE（CVE-2019-17558）与 Log4j 链（CVE-2021-44228）。",
    "升级 Solr 至 8.11.2+；Admin API 加认证并禁止外网访问",
    fw="solr", conf="high", prio=1)
add("x3-java-ofbiz-xmlrpc", "OFBiz XML-RPC 未授权", "java", "deserialization", "critical",
    r"(?:/webtools/control/xmlrpc|/webtools/control/ProgramExport)",
    "OFBiz webtools 端点未授权，存在 XML-RPC 反序列化（CVE-2023-49070 / CVE-2023-51467）与 ProgramExport Groovy 执行。",
    "升级 OFBiz 至 18.12.15+；禁用 webtools 匿名访问",
    fw="ofbiz", conf="high", prio=1)
add("x3-java-xmldecoder", "XMLDecoder 反序列化", "java", "deserialization", "critical",
    r"new\s+XMLDecoder\s*\(",
    "使用 XMLDecoder 解析外部 XML 可实例化任意类并执行代码，是 WebLogic 反序列化链的核心 gadget。",
    "禁止使用 XMLDecoder 处理不可信数据；改用 JSON + 白名单",
    conf="high", prio=1)
add("x3-java-scriptengine", "ScriptEngine 求值外部输入", "java", "rce", "high",
    r"(?:ScriptEngineManager\s*\(\s*\)[\s\S]{0,200}?\.eval\s*\(|getEngineByName\s*\(\s*[\"'](?:js|nashorn|groovy)[\"'])",
    "使用 ScriptEngine 执行脚本，若脚本内容含外部输入则任意代码执行。",
    "禁止对不可信输入求值；使用表达式白名单或替换为规则引擎",
    conf="medium")
add("x3-java-jndi-datasource-inject", "数据源 JNDI 名称可控", "java", "rce", "high",
    r"(?:setUrl\s*\(\s*[^)]{0,60}?(?:getParameter|getHeader)|DriverManager\.getConnection\s*\(\s*[^)]{0,60}?\+)",
    "JDBC URL 或数据源名称由外部参数拼接，可指向恶意 JDBC 驱动实现反序列化 RCE（JDBC 攻击链家族）。",
    "JDBC URL 白名单化；禁止外部输入进入 DriverManager.getConnection",
    conf="high")
add("x3-java-mybatis-inject", "MyBatis ${} 拼接 SQL", "java", "sqli", "high",
    r"(?:select|insert|update|delete)[^<]{0,200}\$\{\s*\w+\s*\}",
    "MyBatis Mapper 中使用 ${} 而非 #{}，参数直接拼接进 SQL，存在注入。",
    "改为 #{} 预编译占位；确实需要拼接时做严格白名单校验",
    fw="mybatis", conf="high", prio=1)
add("x3-java-jpa-inject", "JPA/Hibernate HQL 拼接", "java", "sqli", "high",
    r"createQuery\s*\(\s*[\"'][^\"']{0,120}?[\"']\s*\+",
    "HQL/JPQL 由字符串拼接构造，外部输入可注入 HQL 片段。",
    "使用 setParameter 命名参数绑定",
    fw="hibernate")

# ============================================================
# 二、PHP 生态
# ============================================================
add("x3-php-thinkphp-version", "ThinkPHP 版本低于修复版", "php", "rce", "critical",
    r"(?:const\s+VERSION\s*=\s*[\"'](?:5\.[01]\.\d{1,2}|6\.0\.\d{1,2}|6\.1\.[0-2])[\"'])",
    "ThinkPHP 版本处于历史 RCE 高发区间（5.0.x / 5.1.x / 6.0.x / 6.1.0-6.1.2），存在多参数 RCE 家族（如 CVE-2022-47945、CVE-2023-xxx 多参数注入）。",
    "升级至 ThinkPHP 6.1.3+ / 8.x；开启强制路由并关闭调试模式",
    fw="thinkphp", conf="high", prio=1)
add("x3-php-thinkphp-invoke", "ThinkPHP 动态方法调用", "php", "rce", "high",
    r"(?:call_user_func(?:_array)?\s*\(\s*\$this->request->(?:param|get|post)|\$this->request->(?:param|get|post)\(['\"](?:function|filter|callback))",
    "ThinkPHP 控制器中把请求参数直接作为回调/过滤器使用，可构造任意函数调用。",
    "禁止把请求参数当 callable；使用固定方法映射表",
    fw="thinkphp", conf="high")
add("x3-php-laravel-debug", "Laravel APP_DEBUG 开启 + 弱 key", "php", "info-leak", "high",
    r"(?:APP_DEBUG\s*=\s*true[\s\S]{0,400}?APP_KEY\s*=\s*(?:base64:)?(?:[A-Za-z0-9+/=]{0,20})?\s*$)",
    "生产环境开启 APP_DEBUG 会泄露堆栈与环境变量；APP_KEY 过短/为空可导致反序列化与 Cookie 伪造。",
    "APP_DEBUG=false；APP_KEY 使用 32 字节随机值（php artisan key:generate）",
    fw="laravel", conf="high", prio=1)
add("x3-php-laravel-ignition", "Laravel Ignition RCE 端点", "php", "rce", "critical",
    r"(?:/_ignition/execute-solution|facade/ignition|Ignition\\Solutions)",
    "存在 Ignition 错误页组件且 debug 开启，可触发 CVE-2021-3129 反序列化/RCE。",
    "升级 facade/ignition 至 2.5.2+；关闭 debug",
    fw="laravel", conf="high", prio=1)
add("x3-php-wordpress-plugin-upload", "WordPress 插件任意文件上传", "php", "upload", "critical",
    r"(?:wp_ajax_nopriv_\w+[\s\S]{0,300}?move_uploaded_file|wp_handle_upload[\s\S]{0,200}?\$_(?:FILES|POST))",
    "WordPress 插件注册了 nopriv AJAX 上传处理且未校验扩展名/MIME，是插件上传 RCE 的典型根因。",
    "校验扩展名白名单 + wp_check_filetype_and_ext；限制上传目录不可执行",
    fw="wordpress", conf="high", prio=1)
add("x3-php-wordpress-xmlrpc", "WordPress XML-RPC 开启", "php", "auth-bypass", "medium",
    r"(?:xmlrpc_enabled[\s\S]{0,80}?true|/xmlrpc\.php)",
    "XML-RPC 开启可被用于密码爆破（system.multicall 放大）与 pingback SSRF。",
    "禁用 xmlrpc（add_filter('xmlrpc_enabled','__return_false')）；WAF 拦截 multicall",
    fw="wordpress")
add("x3-php-drupal-drupalgeddon", "Drupal 表单 API 注入特征", "php", "rce", "critical",
    r"(?:Drupal::formBuilder|#post_render|drupal_render)[\s\S]{0,200}?(?:call_user_func|\$form_state)",
    "Drupal 表单渲染链可被构造成 callable 注入（CVE-2018-7600 / CVE-2018-7602 家族）。",
    "升级 Drupal 至受支持版本；禁用匿名访问高风险表单",
    fw="drupal", conf="medium")
add("x3-php-joomla-object-inject", "Joomla 对象注入特征", "php", "deserialization", "high",
    r"(?:JDatabaseDriver|JFactory::getConfig)[\s\S]{0,200}?unserialize\s*\(",
    "Joomla 组件中 unserialize 外部数据，可构造 POP 链（CVE-2015-8562 家族延续）。",
    "禁止 unserialize 用户输入；使用 json_decode",
    fw="joomla", conf="medium")
add("x3-php-dedecms-tpl", "DedeCMS 模板/上传特征", "php", "rce", "high",
    r"(?:/dede/(?:tpl\.php|file_manage|uploads)|SetTemplate|GetTempletFile)",
    "DedeCMS 后台模板与文件管理功能历史存在任意文件写入/上传 RCE（CVE-2022-23337 等）。",
    "删除 /dede 目录或限制内网访问；升级至最新版并改名后台路径",
    fw="dedecms", conf="medium")
add("x3-php-discuz-authkey", "Discuz 弱 authkey / UC_KEY", "php", "auth-bypass", "high",
    r"(?:UC_KEY\s*=\s*['\"][^'\"]{0,12}['\"]|\$config\['security'\]\['authkey'\]\s*=\s*['\"][^'\"]{0,12}['\"])",
    "Discuz/UCenter 密钥过短或默认值，可伪造 Cookie 登录后台（CVE-2019-xxxx 家族）。",
    "重新生成 64 位随机 authkey/UC_KEY；限制 uc_server 外网访问",
    fw="discuz", conf="medium")
add("x3-php-phpmyadmin-sqli", "phpMyAdmin 版本/端点特征", "php", "sqli", "high",
    r"(?:/phpmyadmin/(?:index\.php\?|sql\.php|import\.php)|PMA_VERSION)",
    "phpMyAdmin 历史 SQL 注入与 LFI 漏洞较多（CVE-2020-xxxx 系列）。需确认版本。",
    "升级 phpMyAdmin 至 5.2.x 最新；禁止外网暴露",
    fw="phpmyadmin", conf="medium")
add("x3-php-phpunit-eval", "PHPUnit eval-stdin.php 暴露", "php", "rce", "critical",
    r"(?:/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php)",
    "PHPUnit eval-stdin.php 可 POST 任意 PHP 代码执行（CVE-2017-9841），大量框架默认包含。",
    "生产环境删除 vendor/phpunit 目录；Web 层拦截 /vendor/ 访问",
    fw="phpunit", conf="high", prio=1)
add("x3-php-ueditor-ssrf", "UEditor 上传/SSRF 端点", "php", "upload", "critical",
    r"(?:/ueditor/(?:php|jsp|net)/(?:controller|action)\.(?:php|jsp)|imageUrlPrefix[\s\S]{0,120}?catchimage)",
    "UEditor 的 catchimage 接口可 SSRF 拉取远程文件并落盘，配合上传配置可 getshell。",
    "升级 UEditor 至最新并加固 config.json（禁止 catchimage 外网）；上传目录禁执行",
    fw="ueditor", conf="high", prio=1)
add("x3-php-thinkphp-cache-rce", "框架缓存文件写入可控", "php", "file-write", "high",
    r"(?:file_put_contents\s*\(\s*[^,]{0,60}?\.(?:php|phtml)[\"']?\s*,\s*\$_(?:GET|POST|REQUEST))",
    "直接把请求参数写入 .php 文件，构成任意文件写入 getshell。",
    "禁止把外部输入写入可执行目录；使用非 php 扩展名并做内容转义",
    conf="high", prio=1)
add("x3-php-var-export-eval", "var_export/assert 组合执行", "php", "rce", "high",
    r"(?:assert\s*\(\s*\$_(?:GET|POST|REQUEST)|preg_replace\s*\(\s*['\"][^'\"]*?/e['\"])",
    "assert 直接执行请求参数，或 preg_replace /e 修饰符执行替换结果，均为任意代码执行。",
    "禁止 assert/eval 接收外部输入；preg_replace_callback 替代 /e",
    conf="high", prio=1)
add("x3-php-phar-deser", "phar:// 触发反序列化", "php", "deserialization", "high",
    r"(?:file_exists|is_file|filesize|getimagesize|md5_file|file_get_contents)\s*\(\s*[^)]{0,60}?phar://",
    "文件操作函数接收 phar:// 包装器，可在不调用 unserialize 的情况下触发 POP 链（PHP < 8.0 默认）。",
    "升级 PHP 至 8.0+；校验路径前缀并禁用 phar 包装器",
    conf="high")
add("x3-php-session-upload", "session.upload_progress 竞争包含", "php", "lfi", "high",
    r"(?:session\.upload_progress\.enabled\s*=\s*On|include\s*\(\s*['\"]?/tmp/sess_)",
    "开启 session.upload_progress 且存在本地包含时，可写入 session 文件并竞争包含 getshell。",
    "关闭 session.upload_progress.enabled；包含路径白名单",
    conf="medium")
add("x3-php-pearcmd", "pearcmd.php LFI 转 RCE", "php", "lfi", "high",
    r"(?:/usr/local/lib/php/pearcmd\.php|pearcmd\.php\?\+config-create)",
    "存在 pearcmd.php 且可本地包含时，可通过 config-create 写 webshell。",
    "删除 pearcmd.php；包含路径白名单",
    conf="medium")
add("x3-php-unserialize-input", "unserialize 接收请求参数", "php", "deserialization", "critical",
    r"unserialize\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)",
    "unserialize 直接处理请求参数，配合 POP 链可 RCE。",
    "改用 json_decode；确需序列化时使用签名 + 类白名单（allowed_classes）",
    conf="high", prio=1)
add("x3-php-extract-input", "extract/parse_str 变量覆盖", "php", "auth-bypass", "high",
    r"(?:extract\s*\(\s*\$_(?:GET|POST|REQUEST)|parse_str\s*\(\s*\$_(?:GET|POST|REQUEST))",
    "extract/parse_str 处理请求参数可覆盖本地变量（如 $isAdmin），导致鉴权绕过。",
    "禁止对请求参数使用 extract；parse_str 必须传第二参数",
    conf="high")
add("x3-php-include-input", "include 直接包含请求参数", "php", "lfi", "critical",
    r"(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)",
    "include/require 直接包含请求参数，可 LFI 读取任意文件或 RFI/日志包含 getshell。",
    "使用固定白名单映射文件名；关闭 allow_url_include",
    conf="high", prio=1)
add("x3-php-simplexml-xxe", "simplexml 未禁用外部实体", "php", "xxe", "high",
    r"simplexml_load_string\s*\([^)]{0,200}\)",
    "simplexml_load_string 默认不加载外部实体（PHP>=8），但 7.x 下若未显式传 LIBXML_NONET 仍可能受 XXE 影响，需确认版本。",
    "使用 libxml_disable_entity_loader(true) 或传 LIBXML_NONET；升级 PHP 8+",
    conf="low")
add("x3-php-curl-ssrf", "curl 目标 URL 可控", "php", "ssrf", "high",
    r"curl_setopt\s*\(\s*\$ch\s*,\s*CURLOPT_URL\s*,\s*[^)]{0,80}?\$_(?:GET|POST|REQUEST)",
    "CURLOPT_URL 由请求参数决定，构成 SSRF，可探测内网与云元数据。",
    "URL 域名白名单；禁止访问 169.254.169.254 与内网段",
    conf="high", prio=1)
add("x3-php-file-get-contents-url", "file_get_contents 远程 URL", "php", "ssrf", "medium",
    r"file_get_contents\s*\(\s*[^)]{0,60}?\$_(?:GET|POST|REQUEST)",
    "file_get_contents 接收请求参数，可读取本地文件或发起 SSRF。",
    "路径白名单；关闭 allow_url_fopen",
    conf="high")
add("x3-php-header-inject", "header 拼接未过滤换行", "php", "crlf", "medium",
    r"header\s*\(\s*[\"'][^\"']{0,60}?\$_(?:GET|POST|REQUEST)",
    "header() 拼接请求参数且未过滤 CR/LF，可响应拆分或注入 Set-Cookie。",
    "过滤 \\r\\n；使用框架的 Response 对象",
    conf="medium")
add("x3-php-eval-obfuscated", "eval 混淆后门特征", "php", "rce", "critical",
    r"(?:eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(|\$[a-z]\w*\s*=\s*['\"]\\\\x[0-9a-f]{2})",
    "eval 配合 base64/gzinflate 等解码函数，是 webshell 与后门的典型特征。",
    "定位并删除后门文件；排查上传与写入入口",
    conf="high", prio=1)
add("x3-php-create-function", "create_function 代码执行", "php", "rce", "high",
    r"create_function\s*\(\s*[\"'][^\"']*[\"']\s*,",
    "create_function 内部等同 eval，参数可控时任意代码执行（PHP 7.2 起废弃）。",
    "改用匿名函数；升级 PHP 8+",
    conf="medium")
add("x3-php-dynamic-call", "可变函数调用可控", "php", "rce", "high",
    r"\$(?:_GET|_POST|_REQUEST)\s*\[[^\]]{1,40}\]\s*\(",
    "以请求参数作为函数名直接调用（如 $_GET['f']()），可调用 system/assert 等危险函数。",
    "使用白名单映射表限制可调用函数",
    conf="high", prio=1)

# ============================================================
# 三、Python / Node / Go
# ============================================================
add("x3-py-pickle-request", "pickle 反序列化请求体", "python", "deserialization", "critical",
    r"pickle\.loads?\s*\(\s*(?:request\.|base64\.b64decode|self\.request)",
    "pickle 直接反序列化请求数据，可构造 __reduce__ 执行任意命令。",
    "改用 json；确需 pickle 时使用 HMAC 签名校验",
    conf="high", prio=1)
add("x3-py-jinja-ssti", "render_template_string 渲染请求参数", "python", "ssti", "critical",
    r"(?:render_template_string|Template\s*\(\s*)[^)]{0,80}?(?:request\.|f[\"']|\.format\()",
    "模板字符串由请求参数拼接后渲染，构成 Jinja2 SSTI，可读取配置并 RCE。",
    "使用 render_template 固定模板文件；禁止拼接用户输入进模板源",
    fw="flask", conf="high", prio=1)
add("x3-py-django-debug", "Django DEBUG=True", "python", "info-leak", "medium",
    r"DEBUG\s*=\s*True",
    "Django DEBUG=True 会泄露堆栈、SQL 与设置，且默认返回详细错误页。",
    "生产环境 DEBUG=False；ALLOWED_HOSTS 显式配置",
    fw="django", conf="high")
add("x3-py-django-secret", "Django SECRET_KEY 硬编码/过短", "python", "weak-crypto", "high",
    r"SECRET_KEY\s*=\s*[\"'][^\"']{0,30}[\"']",
    "SECRET_KEY 硬编码或过短，可伪造 session 与签名令牌。",
    "从环境变量读取 50 位随机 SECRET_KEY",
    fw="django", conf="high")
add("x3-py-django-sqli-raw", "Django raw/extra SQL 拼接", "python", "sqli", "high",
    r"(?:\.raw\s*\(\s*f[\"']|\.extra\s*\(\s*where\s*=\s*\[?\s*f[\"']|cursor\.execute\s*\(\s*f[\"'])",
    "使用 f-string 构造原生 SQL，外部输入可注入。",
    "使用参数化查询（%s 占位 + params 元组）",
    fw="django", conf="high", prio=1)
add("x3-py-subprocess-shell", "subprocess shell=True 拼接", "python", "rce", "high",
    r"subprocess\.(?:run|call|Popen|check_output)\s*\(\s*f?[\"'][^\"']{0,80}\{?[^)]{0,60}shell\s*=\s*True",
    "subprocess 开启 shell=True 且命令含变量插值，外部输入可注入 shell 命令。",
    "改用列表参数 + shell=False；必须用 shell 时做 shlex.quote",
    conf="high", prio=1)
add("x3-py-eval-input", "eval/exec 处理请求数据", "python", "rce", "critical",
    r"(?:eval|exec)\s*\(\s*(?:request\.|self\.request|input\s*\()",
    "eval/exec 直接执行请求数据，任意代码执行。",
    "改用 ast.literal_eval 或 json.loads",
    conf="high", prio=1)
add("x3-py-flask-sendfile", "send_file 路径可控", "python", "lfi", "high",
    r"send_file\s*\(\s*(?:request\.|os\.path\.join\s*\([^)]{0,60}?request\.)",
    "send_file 路径来自请求参数，可目录穿越读取任意文件。",
    "使用 send_from_directory + 文件名白名单",
    fw="flask", conf="high")
add("x3-py-jupyter-token", "Jupyter 无 token 启动", "python", "rce", "critical",
    r"(?:--NotebookApp\.token\s*=\s*[\"']{2}|c\.NotebookApp\.token\s*=\s*[\"']{2}|--allow-root)",
    "Jupyter 以空 token / allow-root 启动，未授权即可新建终端执行命令。",
    "设置强 token 或密码；绑定 127.0.0.1",
    fw="jupyter", conf="high", prio=1)
add("x3-py-airflow-fernet", "Airflow 默认/空 fernet key", "python", "weak-crypto", "high",
    r"fernet_key\s*=\s*[\"']{0,10}[\"']|FERNET_KEY\s*=\s*[\"'][^\"']{0,10}[\"']",
    "Airflow fernet_key 为空或默认值，可解密/伪造连接凭据。",
    "生成 32 字节 base64 fernet key 并从环境变量注入",
    fw="airflow", conf="medium")
add("x3-py-gradio-share", "Gradio share=True 公网暴露", "python", "info-leak", "medium",
    r"(?:\.launch\s*\([^)]{0,120}?share\s*=\s*True|server_name\s*=\s*[\"']0\.0\.0\.0[\"'])",
    "Gradio 以 share=True 或 0.0.0.0 暴露，历史存在任意文件读取（CVE-2023-51449 家族）。",
    "生产禁用 share；限制来源 IP 并升级 gradio",
    fw="gradio", conf="medium")
add("x3-node-childprocess", "child_process 拼接执行", "nodejs", "rce", "high",
    r"(?:child_process[\s\S]{0,40}?)?(?:exec|execSync|spawnSync)\s*\(\s*(?:`[^`]{0,80}\$\{|[^)]{0,60}?\+\s*req\.)",
    "child_process.exec 拼接请求参数，可注入 shell 命令。",
    "改用 execFile + 参数数组；对输入做白名单校验",
    conf="high", prio=1)
add("x3-node-eval-input", "eval/new Function 处理请求", "nodejs", "rce", "critical",
    r"(?:eval|new\s+Function)\s*\(\s*(?:req\.|request\.|ctx\.request)",
    "eval/new Function 执行请求数据，任意代码执行。",
    "禁止 eval；使用 JSON.parse 或表达式白名单",
    conf="high", prio=1)
add("x3-node-prototype-merge", "对象合并原型污染", "nodejs", "prototype-pollution", "high",
    r"(?:_\.(?:merge|defaultsDeep|set)\s*\(\s*[^,]{0,40},\s*req\.(?:body|query)|Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.body|deepmerge\s*\()",
    "使用 lodash.merge/deepmerge/Object.assign 合并请求体，可注入 __proto__ 污染原型链。",
    "使用 Object.create(null) + 键名黑名单（__proto__/constructor/prototype）；升级 lodash 至 4.17.21+",
    conf="high", prio=1)
add("x3-node-jwt-none", "JWT 显式允许 alg=none", "nodejs", "jwt", "critical",
    r"(?:algorithms\s*:\s*\[\s*[\"']none[\"']|algorithm\s*=\s*[\"']none[\"'])",
    "JWT 校验白名单包含 none，攻击者可去掉签名直接伪造任意身份。",
    "移除 none；verify 时显式指定 algorithms:['RS256']",
    fw="jsonwebtoken", conf="high", prio=1)
add("x3-node-jwt-verify", "JWT 校验需确认算法白名单", "nodejs", "jwt", "medium",
    r"jwt\.verify\s*\(",
    "存在 jwt.verify 调用，需确认是否显式指定 algorithms 白名单；未指定时可被算法混淆绕过（CVE-2022-23529 家族）。",
    "verify 时显式指定 algorithms:['RS256']；升级 jsonwebtoken 至 9.0.0+",
    fw="jsonwebtoken", conf="low")
add("x3-node-lodash-version", "lodash 低于 4.17.21", "nodejs", "prototype-pollution", "high",
    r"[\"']lodash[\"']\s*:\s*[\"'](?:[0-3]\.[\d.]+|4\.(?:[0-9]|1[0-6])\.[\d]+)[\"']",
    "lodash 版本低于 4.17.21，存在命令注入（CVE-2021-23337）与原型污染（CVE-2020-8203）风险。",
    "升级 lodash 至 4.17.21+",
    fw="lodash")
add("x3-node-express-version", "Express 低于 4.17.3", "nodejs", "info-leak", "medium",
    r"[\"']express[\"']\s*:\s*[\"']4\.(?:[0-9]|1[0-6])\.[\d]+[\"']",
    "Express 版本偏低，存在 qs 原型污染（CVE-2022-24999）与 open redirect 等风险。",
    "升级 express 至 4.17.3+ / 5.x",
    fw="express")
add("x3-node-next-middleware", "Next.js middleware 鉴权绕过特征", "nodejs", "auth-bypass", "high",
    r"(?:middleware\.ts|middleware\.js)[\s\S]{0,400}?matcher\s*:\s*\[[^\]]{0,200}?/api",
    "Next.js middleware matcher 覆盖不全时，带 x-middleware-subrequest 头可绕过鉴权（CVE-2025-29927 家族）。",
    "升级 Next.js 至 15.2.3+ / 14.2.25+；在 API 路由内二次鉴权",
    fw="next.js", conf="medium")
add("x3-go-command-shell", "Go exec 拼接 sh -c", "go", "rce", "high",
    r"exec\.Command(?:Context)?\s*\(\s*[\"'](?:sh|bash|cmd)[\"']\s*,\s*[\"'](?:-c|/c)[\"']",
    "exec.Command 通过 sh -c 执行拼接命令，外部输入可注入。",
    "exec.Command 直接传程序名 + 参数切片，不经过 shell",
    conf="high", prio=1)
add("x3-go-sql-concat", "Go SQL 字符串拼接", "go", "sqli", "high",
    r"(?:db\.(?:Query|Exec|QueryRow)(?:Context)?)\s*\(\s*[^,)]{0,40}?\+",
    "SQL 语句由字符串拼接构造，外部输入可注入。",
    "使用 ? / $1 占位参数",
    conf="high")
add("x3-go-path-traversal", "Go 文件路径未清洗", "go", "lfi", "high",
    r"(?:os\.(?:Open|ReadFile)|ioutil\.ReadFile|http\.ServeFile)\s*\(\s*[^)]{0,60}?(?:r\.URL|r\.FormValue|r\.PathValue)",
    "文件路径来自请求，未做 filepath.Clean + 前缀校验时可目录穿越。",
    "filepath.Clean 后校验前缀；使用 embed.FS 或固定白名单",
    conf="medium")
add("x3-go-pprof-exposed", "net/http/pprof 暴露", "go", "info-leak", "medium",
    r"(?:\"net/http/pprof\"|/debug/pprof/)",
    "导入 net/http/pprof 并挂在公网端口，会泄露 goroutine/堆栈，且 /debug/pprof/heap 可下载内存。",
    "仅在内部端口注册 pprof；生产禁用",
    conf="high")

# ============================================================
# 四、中间件 / 设备 / 通用指纹
# ============================================================
add("x3-mid-nginx-alias", "Nginx alias 目录穿越配置", "mixed", "lfi", "high",
    r"location\s+[^{]{0,40}\{[\s\S]{0,200}?alias\s+[^;]{0,80}/;",
    "Nginx alias 配置缺少结尾斜杠或 location 未用 ^~，可目录穿越读取配置（CVE-2021-23017 家族外的常见错配）。",
    "location 与 alias 同时以 / 结尾，或用 root 替代 alias",
    fw="nginx", conf="medium")
add("x3-mid-apache-cgi", "Apache CGI 目录可执行", "mixed", "rce", "high",
    r"(?:ScriptAlias\s+/cgi-bin|Options\s+[^\n]{0,40}ExecCGI)",
    "开启 CGI 执行且 cgi-bin 可写/含历史漏洞组件（CVE-2021-41773 / CVE-2021-42013 路径穿越）。",
    "升级 Apache 至 2.4.51+；cgi-bin 目录不可写且限制访问",
    fw="apache", conf="medium")
add("x3-mid-apache-traversal-version", "Apache 2.4.49/2.4.50 路径穿越", "mixed", "lfi", "critical",
    r"(?:Apache/2\.4\.(?:49|50))",
    "Apache HTTP Server 2.4.49/2.4.50 存在路径穿越与 RCE（CVE-2021-41773 / CVE-2021-42013）。",
    "升级 Apache 至 2.4.51+",
    fw="apache", conf="high", prio=1)
add("x3-mid-redis-unauth", "Redis 无密码/绑定 0.0.0.0", "mixed", "rce", "critical",
    r"(?m)^\s*(?:bind\s+0\.0\.0\.0|protected-mode\s+no|requirepass\s*$)",
    "Redis 绑定 0.0.0.0 且未设密码或关闭保护模式，可未授权写入 crontab/SSH key 或主从复制 RCE。",
    "bind 127.0.0.1；设置 requirepass；protected-mode yes",
    fw="redis", conf="high", prio=1)
add("x3-mid-mysql-root-nopass", "MySQL root 空口令/远程 root", "mixed", "info-leak", "high",
    r"(?:GRANT\s+ALL[\s\S]{0,60}?TO\s+[\"']?root[\"']?@[\"']%|skip-grant-tables)",
    "MySQL 允许 root 从任意主机登录或启用 skip-grant-tables，等于无鉴权。",
    "限制 root@localhost；删除 skip-grant-tables；使用最小权限账号",
    fw="mysql", conf="high")
add("x3-mid-es-unauth", "Elasticsearch 未授权", "mixed", "info-leak", "critical",
    r"(?:xpack\.security\.enabled\s*:\s*false|http\.port\s*:\s*9200[\s\S]{0,200}?network\.host\s*:\s*0\.0\.0\.0)",
    "Elasticsearch 关闭安全模块并对外监听，未授权即可读写索引（含 CVE-2014-3120 脚本 RCE 家族）。",
    "开启 xpack.security；绑定内网地址；升级至 8.x 默认开启安全",
    fw="elasticsearch", conf="high", prio=1)
add("x3-mid-docker-api", "Docker API 未授权", "mixed", "rce", "critical",
    r"(?:/var/run/docker\.sock|tcp://0\.0\.0\.0:2375|DOCKER_HOST\s*=\s*tcp://)",
    "Docker daemon 暴露 TCP 或挂载 socket，等于宿主 root：可挂载 / 启动特权容器逃逸。",
    "仅 unix socket；启用 TLS 双向认证；禁止容器挂载 docker.sock",
    fw="docker", conf="high", prio=1)
add("x3-mid-k8s-anonymous", "K8s 匿名访问 / 特权 Pod", "mixed", "rce", "critical",
    r"(?:--anonymous-auth\s*=\s*true|privileged\s*:\s*true|hostPath\s*:\s*\n?\s*path\s*:\s*/)",
    "Kubernetes 允许匿名认证或 Pod 使用 privileged/hostPath 挂载宿主根目录，可逃逸至节点。",
    "关闭 anonymous-auth；禁用 privileged 与 hostPath（PSP/OPA 策略）",
    fw="kubernetes", conf="high", prio=1)
add("x3-mid-grafana-default", "Grafana 默认口令/插件签名关闭", "mixed", "auth-bypass", "high",
    r"(?:allow_sign_up\s*=\s*true|GF_SECURITY_ADMIN_PASSWORD\s*=\s*admin|admin_password\s*=\s*admin)",
    "Grafana 允许自助注册或使用 admin 默认口令，可登录后利用数据源 SSRF（CVE-2021-43798 任意文件读取）。",
    "修改 admin 口令并关闭 allow_sign_up；升级至 8.3.1+",
    fw="grafana", conf="high")
add("x3-mid-zabbix-sqli", "Zabbix 版本/端点特征", "mixed", "sqli", "high",
    r"(?:/zabbix/(?:index|jsrpc)\.php|ZABBIX_VERSION)",
    "Zabbix 历史存在 SQL 注入（CVE-2024-22120 等）与默认口令 Admin/zabbix。",
    "升级 Zabbix 至 6.0.31+ / 6.4.16+；修改默认口令",
    fw="zabbix", conf="medium")
add("x3-mid-fortinet-ssl", "Fortinet SSL-VPN 端点", "mixed", "rce", "critical",
    r"(?:/remote/login|/remote/fgt_lang|/sslvpn/|FortiGate)",
    "Fortinet SSL-VPN 端点暴露，历史存在 CVE-2018-13379 路径穿越与 CVE-2022-42475 / CVE-2023-27997 堆溢出。",
    "升级 FortiOS 至最新；限制 SSL-VPN 来源；强制 MFA",
    fw="fortinet", conf="high", prio=1)
add("x3-mid-citrix-adc", "Citrix ADC/Gateway 端点", "mixed", "rce", "critical",
    r"(?:/vpn/../vpns/|/Citrix/|citrix\.xml|/nf/auth/)",
    "Citrix ADC/Gateway 端点暴露，存在 CVE-2019-19781 路径穿越与 CVE-2023-3519 RCE。",
    "升级至修复版本；限制管理接口来源",
    fw="citrix", conf="high", prio=1)
add("x3-mid-exchange-proxy", "Exchange ProxyLogon 路径", "mixed", "rce", "critical",
    r"(?:/ecp/[^\"']*|/owa/auth/|/autodiscover/autodiscover\.xml|/mapi/)",
    "Exchange 端点暴露，历史存在 ProxyLogon（CVE-2021-26855）与 ProxyShell（CVE-2021-34473）链式 RCE。",
    "打全 Exchange CU 与 SU；限制 /ecp 外网访问",
    fw="exchange", conf="medium")
add("x3-mid-hikvision-unauth", "海康威视设备未授权", "mixed", "info-leak", "high",
    r"(?:/ISAPI/|/SDK/webLanguage|/onvif-http/snapshot)",
    "海康设备 ISAPI 接口历史存在未授权信息泄露与命令注入（CVE-2021-36260）。",
    "升级固件至修复版；设备不暴露公网",
    fw="hikvision", conf="medium")
add("x3-mid-dahua-backdoor", "大华设备后门账号特征", "mixed", "auth-bypass", "high",
    r"(?:/RPC2|/current_config/|Dahua.*888888)",
    "大华设备历史存在内置后门账号（CVE-2017-7921）与 RPC2 未授权。",
    "升级固件；禁用默认账号；限制公网访问",
    fw="dahua", conf="medium")
add("x3-mid-totolink-cmd", "TOTOLINK 命令注入端点", "mixed", "rce", "high",
    r"(?:/cgi-bin/cstecgi\.cgi|/boafrm/form)",
    "家用路由器 CGI 端点（TOTOLINK/D-Link 等）历史存在未授权命令注入。",
    "升级固件；管理口仅内网可达",
    fw="totolink", conf="medium")
add("x3-mid-ruijie-cli", "锐捷设备命令注入特征", "mixed", "rce", "high",
    r"(?:/web_action|/cgi-bin/luci/|ruijie|RGOS)",
    "锐捷/OpenWrt 系设备 Web 接口历史存在命令注入与未授权（如 CVE-2021-xxxx 系列）。",
    "升级固件；限制管理面访问",
    fw="ruijie", conf="low")

# 国产 OA
add("x3-cn-seeyon-oa", "致远 OA 端点/组件特征", "java", "rce", "critical",
    r"(?:/seeyon/(?:htmlofficeservlet|ajax|main.do)|ctpfile|A8Servlet)",
    "致远 OA 历史存在 htmlofficeservlet 任意文件上传、A8 反序列化等 RCE（CVE-2019-xxxx 家族延续）。",
    "升级至官方安全补丁版本；限制 /seeyon 外网访问",
    fw="seeyon", conf="high", prio=1)
add("x3-cn-weaver-oa", "泛微 OA 端点/组件特征", "java", "rce", "critical",
    r"(?:/weaver/(?:ecology|mobile)|/wui/index|E-ecology|weaver\.security)",
    "泛微 e-cology 历史存在 SQL 注入、文件上传与反序列化 RCE（多个 CNVD 编号）。",
    "升级至官方补丁版本；WAF 拦截 /weaver 异常请求",
    fw="weaver", conf="high", prio=1)
add("x3-cn-tongda-oa", "通达 OA 端点/组件特征", "php", "rce", "critical",
    r"(?:/general/(?:appbuilder|document|logincheck)|/ispirit/|tongda|MYOA)",
    "通达 OA 历史存在未授权文件上传、SQL 注入与任意用户登录（多个 CNVD 编号）。",
    "升级至 11.10+ 补丁版；限制 /general 与 /ispirit 外网访问",
    fw="tongda", conf="high", prio=1)
add("x3-cn-zentao-oa", "禅道端点/组件特征", "php", "sqli", "high",
    r"(?:/zentao/(?:index|user-login|api-getModel)|/pro/|/biz/)",
    "禅道历史存在 SQL 注入与越权（多个 CNVD 编号）。",
    "升级至 18.x 修复版；限制外网访问",
    fw="zentao", conf="medium")
add("x3-cn-yonyou-nc", "用友 NC/U8 端点特征", "java", "deserialization", "critical",
    r"(?:/servlet/~ic/|/uapws/|/nc/servlet|yonyou|U8Login)",
    "用友 NC/U8 历史存在反序列化与 XXE RCE（多个 CNVD 编号）。",
    "升级至官方补丁版本；限制 /servlet 与 /uapws 访问",
    fw="yonyou", conf="high", prio=1)

# ============================================================
# 五、通用暴露面 / 敏感文件
# ============================================================
add("x3-exp-git-dir", "源码版本库目录暴露", "mixed", "info-leak", "high",
    r"(?:/\.git/(?:config|HEAD|index)|/\.svn/entries)",
    ".git/.svn 目录可访问，攻击者可还原完整源码并提取数据库口令、密钥。",
    "Web 层拦截 /.* 隐藏目录；部署时排除 VCS 目录",
    conf="high", prio=1)
add("x3-exp-env-file", "环境变量文件暴露", "mixed", "info-leak", "critical",
    r"(?:/\.env(?:\.[a-z]+)?[\"'\s]|APP_ENV=|DB_PASSWORD=)",
    ".env 可访问或被打进镜像，泄露数据库口令、APP_KEY、云 AK。",
    "Web 层拦截 /.env；构建时排除；泄露后立即轮换全部凭据",
    conf="high", prio=1)
add("x3-exp-backup-file", "备份/压缩包暴露", "mixed", "info-leak", "high",
    r"(?:/(?:www|web|backup|db|site)\.(?:zip|tar\.gz|rar|7z|sql)|\.php\.(?:bak|swp|old|txt))",
    "站点备份、SQL 导出或编辑器临时文件可下载，泄露源码与数据。",
    "删除备份文件；拦截危险扩展名；部署流水线做产物扫描",
    conf="high")
add("x3-exp-actuator", "Spring Actuator 端点暴露", "java", "info-leak", "high",
    r"(?:/actuator/(?:env|heapdump|mappings|beans|httptrace|gateway)|management\.endpoints\.web\.exposure\.include\s*=\s*\*)",
    "Actuator 端点全开，/env 泄露口令、/heapdump 可下载内存提取凭据、/gateway 可写路由 RCE。",
    "只暴露 health/info；生产加认证并限制来源",
    fw="spring", conf="high", prio=1)
add("x3-exp-swagger", "Swagger/API 文档暴露", "mixed", "info-leak", "low",
    r"(?:/swagger-ui(?:\.html|/index\.html)|/v2/api-docs|/v3/api-docs|/openapi\.json)",
    "接口文档对外暴露，泄露全部内部 API 与参数结构，便于进一步攻击。",
    "生产关闭文档或加认证",
    conf="high")
add("x3-exp-druid", "Druid 监控台未授权", "java", "info-leak", "high",
    r"(?:/druid/(?:index\.html|websession|sql\.json|api\.json))",
    "Druid 监控台未授权可查看 SQL 与会话，历史存在 Session 泄露导致登录绕过。",
    "设置 loginUsername/loginPassword；限制 /druid 访问",
    fw="druid", conf="high", prio=1)
add("x3-exp-jmx-console", "JBoss JMX 控制台暴露", "java", "rce", "critical",
    r"(?:/jmx-console/|/invoker/JMXInvokerServlet|/invoker/EJBInvokerServlet)",
    "JBoss JMX/Invoker 未授权，可部署 WAR 或反序列化 RCE。",
    "删除 invoker 与 jmx-console；升级至受支持版本",
    fw="jboss", conf="high", prio=1)
add("x3-exp-harbor-unauth", "Harbor/Registry 未授权", "mixed", "info-leak", "high",
    r"(?:/v2/_catalog|/api/v2\.0/projects)",
    "容器镜像仓库 API 未授权，可拉取镜像并从中提取凭据与源码。",
    "开启认证；限制 /v2 外网访问",
    fw="harbor", conf="medium")
add("x3-exp-k8s-api", "Kubernetes API 未授权", "mixed", "rce", "critical",
    r"(?:/api/v1/namespaces|/apis/apps/v1|/version\?timeout)",
    "Kubernetes API Server 未授权可创建特权 Pod 逃逸到节点。",
    "关闭匿名认证；RBAC 最小权限；API 仅集群内可达",
    fw="kubernetes", conf="medium")
add("x3-exp-metrics", "Prometheus 指标泄露", "mixed", "info-leak", "low",
    r"(?:/metrics\b|prometheus\.io/client_golang)",
    "/metrics 暴露内部主机名、版本、调用量，可用于资产测绘。",
    "加认证或仅内网抓取",
    conf="medium")
add("x3-exp-graphql-introspection", "GraphQL 内省开启", "mixed", "graphql", "medium",
    r"(?:introspection\s*:\s*true|__schema\s*\{)",
    "GraphQL 内省未关闭，可枚举全部类型与字段，便于构造越权查询。",
    "生产关闭 introspection；按字段做鉴权",
    conf="high")
add("x3-exp-cors-wildcard", "CORS 通配 + 携带凭据", "mixed", "cors", "high",
    r"(?:Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*[\"'][\s\S]{0,200}?Access-Control-Allow-Credentials[\"']?\s*[:,]\s*[\"']?true)",
    "CORS 同时允许任意源与携带 Cookie，任意站点可读取用户敏感数据。",
    "改为 Origin 白名单反射校验；不要与 credentials 同用 *",
    conf="high", prio=1)
add("x3-exp-csrf-noverify", "关闭 CSRF 防护", "mixed", "csrf", "medium",
    r"(?:csrf\s*\(\s*\)\s*\.\s*disable\s*\(|\.csrf\(\)\.disable\(\)|@EnableWebSecurity[\s\S]{0,200}?csrf\s*\(\s*\)\s*\.\s*disable)",
    "显式关闭 CSRF 防护，配合 Cookie 会话可被跨站请求伪造。",
    "保留 CSRF 防护；API 用 SameSite=Lax/Strict + 自定义头校验",
    conf="high")
add("x3-exp-open-redirect", "跳转目标直接取参数", "mixed", "open-redirect", "medium",
    r"(?:redirect\s*\(\s*(?:request\.|req\.)|header\s*\(\s*[\"']Location:\s*[\"']\s*\.\s*\$_GET|RedirectResponse\s*\(\s*request\.)",
    "跳转地址直接取自请求参数，可被用于钓鱼与 OAuth token 窃取。",
    "跳转目标白名单；仅允许相对路径",
    conf="medium")
add("x3-exp-request-smuggling", "反向代理未规范化 CL/TE", "mixed", "request-smuggling", "high",
    r"(?:proxy_pass[\s\S]{0,300}?;|Transfer-Encoding[\s\S]{0,60}?chunked)",
    "反代配置未拒绝同时带 Content-Length 与 Transfer-Encoding 的请求，存在请求走私风险。",
    "前置代理统一规范化并拒绝 CL+TE 共存；升级 Nginx/HAProxy",
    conf="low")
add("x3-exp-race-coupon", "并发扣减无锁", "mixed", "race-condition", "medium",
    r"(?:SELECT[\s\S]{0,80}?FOR UPDATE|UPDATE[\s\S]{0,60}?SET[\s\S]{0,60}?stock\s*=\s*stock\s*-\s*1)",
    "库存/余额扣减使用非原子读改写或缺少行锁，可并发超卖或重复兑换。",
    "使用 UPDATE ... WHERE stock>0 原子更新；或加 SELECT FOR UPDATE / Redis 分布式锁",
    conf="low")
add("x3-exp-weak-hash", "弱哈希存储口令", "mixed", "weak-crypto", "high",
    r"(?:md5\s*\(\s*(?:password|passwd|pwd)|\bmd5\s*\(\s*\$_(?:POST|GET)\[['\"]?(?:pass|pwd))",
    "口令使用 MD5/SHA1 单次哈希存储，可被彩虹表快速还原。",
    "改用 bcrypt/argon2id（PHP password_hash / Python bcrypt）",
    conf="high", prio=1)
add("x3-exp-debug-true", "生产环境开启调试模式", "mixed", "info-leak", "medium",
    r"(?:debug\s*[:=]\s*(?:true|True|1)\s*[,;\n]|APP_DEBUG\s*=\s*true)",
    "调试模式开启会泄露堆栈、配置与 SQL，并可能触发框架调试端点 RCE（如 Ignition）。",
    "生产关闭 debug；错误页统一化",
    conf="medium")
add("x3-exp-ssrf-metadata", "云元数据地址访问", "mixed", "ssrf", "critical",
    r"(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
    "代码中出现云元数据地址（可能是 SSRF 利用链或危险的健康检查），配合 URL 可控即可窃取实例凭据。",
    "禁止访问元数据地址；启用 IMDSv2 并要求 token",
    conf="medium", prio=1)
add("x3-exp-ldap-inject", "LDAP 过滤器拼接", "mixed", "ldap", "high",
    r"(?:\(uid=\s*[\"']?\s*\+|\(cn=\s*[\"']?\s*\+|search\s*\(\s*[^,]{0,40}?\(\w+=\s*[\"']?\s*\+)",
    "LDAP 查询过滤器由字符串拼接，可注入 *)(uid=* 绕过认证。",
    "转义特殊字符（\\2a \\28 \\29 \\5c \\00）；使用参数化 LDAP API",
    conf="high")
add("x3-exp-xpath-inject", "XPath 查询拼接", "mixed", "xpath", "medium",
    r"(?:selectNodes\s*\(\s*[\"'][^\"']{0,80}?[\"']\s*\+|XPathExpression|/html/body[\s\S]{0,40}\+)",
    "XPath 表达式由字符串拼接，可注入 ' or '1'='1 绕过条件。",
    "使用变量绑定（XPathVariableResolver）而非拼接",
    conf="medium")
add("x3-exp-nosqli-operator", "NoSQL 操作符注入", "mixed", "nosqli", "high",
    r"(?:find\s*\(\s*\{\s*\w+\s*:\s*req\.(?:body|query)|\$ne\s*:\s*[\"']{2}|\$regex\s*:\s*req\.)",
    "MongoDB 查询直接使用请求对象，可注入 $ne/$regex/$where 绕过认证或盲注。",
    "对查询键做类型校验，禁止对象类型进入查询；使用 schema 校验（mongoose strict）",
    conf="high", prio=1)
add("x3-exp-ssrf-host-bypass", "SSRF 黑名单可绕过写法", "mixed", "ssrf", "medium",
    r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|2130706433|0x7f000001)",
    "SSRF 校验使用字符串黑名单（127.0.0.1 等），可被十进制/十六进制/IPv6 绕过。",
    "解析成 IP 后判断私网段（ipaddress 库）；禁止跟随重定向；DNS rebinding 防护",
    conf="medium")


def go_re2_ok(patterns):
    """用 Go 批量校验 RE2 兼容性。"""
    import subprocess
    import tempfile
    src = ["package main", "import (\"fmt\";\"regexp\";\"bufio\";\"os\")",
           "func main(){s:=bufio.NewScanner(os.Stdin);for s.Scan(){l:=s.Text();",
           "if _,e:=regexp.Compile(l);e!=nil{fmt.Println(\"BAD\\t\"+l+\"\\t\"+e.Error())}}}"]
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "main.go")
        open(p, "w").write("\n".join(src))
        r = subprocess.run(["go", "run", p], input="\n".join(patterns),
                           capture_output=True, text=True, cwd=td)
    bad = [l for l in r.stdout.splitlines() if l.startswith("BAD")]
    return bad


def main():
    stats = "--stats" in sys.argv
    existing = set()
    if os.path.exists(DB):
        try:
            con = sqlite3.connect(DB)
            # 只对"别人写的"规则去重；本生成器自己的 x3- 规则忽略，
            # 否则 sync 一次之后再生成就会把自己全过滤掉。
            existing = {r[0] for r in con.execute(
                "select pattern from vulnerability_scan_rules "
                "where rule_id not like 'x3-%'")}
            con.close()
        except Exception as e:
            print(f"! 读 DB 失败（跳过去重）: {e}")

    seen = set()
    out, dup_db, dup_self = [], [], []
    for r in RULES:
        p = r["pattern"]
        if p in existing:
            dup_db.append(r["rule_id"])
            continue
        if p in seen:
            dup_self.append(r["rule_id"])
            continue
        seen.add(p)
        out.append(r)

    print(f"生成规则 {len(RULES)} 条 → 去重后 {len(out)} 条")
    if dup_db:
        print(f"  跳过（DB 已有相同 pattern）{len(dup_db)}: {', '.join(dup_db[:20])}")
    if dup_self:
        print(f"  跳过（本文件重复）{len(dup_self)}: {', '.join(dup_self)}")

    bad = go_re2_ok([r["pattern"] for r in out])
    if bad:
        print(f"! RE2 编译失败 {len(bad)} 条：")
        for b in bad:
            print("   ", b)
        sys.exit(1)
    print(f"  RE2 校验：{len(out)} 条全部通过")

    from collections import Counter
    print("  按语言:", dict(Counter(r["language"] for r in out)))
    print("  按类型:", dict(Counter(r["category"] for r in out)))
    print("  按严重度:", dict(Counter(r["severity"] for r in out)))

    if stats:
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump({"rules": out}, open(OUT, "w"), ensure_ascii=False, indent=1)
    print(f"已写入 {OUT} ({os.path.getsize(OUT)} B)")


if __name__ == "__main__":
    main()
