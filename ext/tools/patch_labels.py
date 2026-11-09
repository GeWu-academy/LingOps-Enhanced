#!/usr/bin/env python3
"""给官方前端 bundle 补中文标签（幂等）。

官方 SPA bundle 是压缩过的构建产物，仓库里不跟踪（只跟踪 lp-ext/ 注入层），
但 AWDP 五个内容库新增的 category / language slug 需要中文标签才好看，
所以用脚本在打包前补一次，保证「从仓库重新打包」也能复现。

用法：
    python3 ext/tools/patch_labels.py            # 自动找 frontend/dist/assets_v2/index-*.js
    python3 ext/tools/patch_labels.py --check    # 只检查是否已补齐，不改文件
"""

import argparse
import glob
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BUNDLE_GLOB = os.path.join(ROOT, "frontend", "dist", "assets_v2", "index-*.js")

# 语言下拉 + 标签表
UT_OLD = '{label:"Node.js",value:"nodejs"},{label:"Go",value:"go"}]'
UT_NEW = ('{label:"Node.js",value:"nodejs"},{label:"Go",value:"go"},'
          '{label:"Ruby",value:"ruby"},{label:"C#",value:"csharp"},{label:"Shell",value:"shell"}]')

KT_OLD = 'kt={php:"PHP",python:"Python",java:"Java",nodejs:"Node.js",go:"Go",mixed:"混合"}'
KT_NEW = ('kt={php:"PHP",python:"Python",java:"Java",nodejs:"Node.js",go:"Go",mixed:"混合",'
          'ruby:"Ruby",csharp:"C#",shell:"Shell"}')

# 分类标签表
ET_OLD = 'jwt:{label:"JWT / 认证",color:"blue"},"auth-bypass":{label:"认证绕过",color:"cyan"}}'
ET_NEW = (
    'jwt:{label:"JWT / 认证",color:"blue"},"auth-bypass":{label:"认证绕过",color:"cyan"},'
    '"file-write":{label:"任意文件写入",color:"red"},'
    '"info-leak":{label:"信息泄露",color:"orange"},'
    'crlf:{label:"CRLF 注入",color:"gold"},'
    'ldap:{label:"LDAP 注入",color:"lime"},'
    'xpath:{label:"XPath 注入",color:"cyan"},'
    '"open-redirect":{label:"开放重定向",color:"geekblue"},'
    '"request-smuggling":{label:"请求走私",color:"volcano"},'
    '"race-condition":{label:"条件竞争",color:"magenta"},'
    'cors:{label:"CORS 配置错误",color:"blue"},'
    'csrf:{label:"CSRF",color:"purple"},'
    '"weak-crypto":{label:"弱加密 / 硬编码密钥",color:"gold"},'
    'graphql:{label:"GraphQL",color:"lime"}}'
)

# 规则列表「来源」筛选表（v1.3.6 起 CVE 家族规则 rule_id 前缀 x3-）
GH_OLD = 'Gh=[{label:"内置",value:"builtin"},{label:"自定义",value:"custom"}]'
GH_NEW = ('Gh=[{label:"内置",value:"builtin"},{label:"自定义",value:"custom"},'
          '{label:"CVE 采集",value:"cve-nvd"}]')
# 早期 v1.3.6 草稿用的是「NVD 采集」，改名后需要能收敛
GH_DRAFT = ('Gh=[{label:"内置",value:"builtin"},{label:"自定义",value:"custom"},'
            '{label:"NVD 采集",value:"cve-nvd"}]')

# 官方后端加载 poc 种子时会把 source_type 一律改写成 builtin，
# 所以「CVE 采集」这一项只能靠 rule_id 前缀识别，不能靠 source_type 字段。
SRC_OLD = '(!he||(R.source_type||"builtin")===he)'
SRC_NEW = ('(!he||(he==="cve-nvd"?(R.rule_id||"").indexOf("x3-")===0'
           ':(he==="builtin"?(R.source_type||"builtin")==="builtin"'
           '&&(R.rule_id||"").indexOf("x3-")!==0'
           ':(R.source_type||"builtin")===he)))')

# 知识库 / 规则列表一次拉 500 条，v1.3.6 起条目破千，改大避免前端截断
KB_PAGE_OLD = '"/api/v1/awdp/knowledge",{params:{page_size:500}}'
KB_PAGE_NEW = '"/api/v1/awdp/knowledge",{params:{page_size:3000}}'
RULE_PAGE_OLD = '"/api/v1/awdp/scan-rules",{params:{page_size:500}}'
RULE_PAGE_NEW = '"/api/v1/awdp/scan-rules",{params:{page_size:3000}}'

PATCHES = (("语言筛选", UT_OLD, UT_NEW), ("语言标签", KT_OLD, KT_NEW),
           ("分类标签", ET_OLD, ET_NEW), ("来源筛选改名", GH_DRAFT, GH_NEW),
           ("来源筛选", GH_OLD, GH_NEW),
           ("来源筛选生效", SRC_OLD, SRC_NEW),
           ("知识库分页", KB_PAGE_OLD, KB_PAGE_NEW),
           ("规则分页", RULE_PAGE_OLD, RULE_PAGE_NEW))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只检查，不写文件")
    args = ap.parse_args()

    files = glob.glob(BUNDLE_GLOB)
    if not files:
        sys.exit("找不到 bundle：%s" % BUNDLE_GLOB)

    rc = 0
    for path in files:
        with open(path, encoding="utf-8") as f:
            s = f.read()
        orig = s
        pending = []
        for name, old, new in PATCHES:
            if new in s:
                continue
            if old not in s:
                print("!! %s 中找不到「%s」锚点，官方 bundle 可能已升级，需人工核对" % (os.path.basename(path), name))
                rc = 1
                continue
            s = s.replace(old, new, 1)
            pending.append(name)
        if not pending:
            print("已是最新：%s" % os.path.basename(path))
            continue
        if args.check:
            print("待补标签（%s）：%s" % (os.path.basename(path), "、".join(pending)))
            rc = 1
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(s)
        print("已补标签（%s）：%s（+%d 字节）" % (os.path.basename(path), "、".join(pending), len(s) - len(orig)))
    return rc


if __name__ == "__main__":
    sys.exit(main())
