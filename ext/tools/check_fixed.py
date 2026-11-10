#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fixed/ 验收脚本 —— 给本地 AI 自查用，也给人生成 review 清单。

用法（在 AI 修复包目录里跑）：
    python3 check_fixed.py              # 全部检查
    python3 check_fixed.py --strict     # 未覆盖 critical/high 也判失败
    python3 check_fixed.py -v           # 打印每条命中的坏模式

退出码 0 = 可以生成补丁；非 0 = 先按报错改 fixed/，别急着 make_patch.py。
"""
import argparse
import difflib
import json
import os
import re
import subprocess
import sys

# 已知会让补丁报废 / 功能坏掉的写法。命中即 FAIL。
BAD_PATTERNS = [
    (r"\bconst\s+\w+\s*=\s*(getenv|env|\\\$_)",
     "PHP 常量不能用函数返回值/变量初始化，会 Fatal error；改成 private static function"),
    (r"\bprivate\s+const\s+\w+\s*=\s*[^'\";\d\s]",
     "PHP 类常量初始化器必须是字面量；改 static function 或普通属性"),
    (r"extract\s*\(\s*\\\$",
     "extract() 变量覆盖仍在；改成显式赋值"),
    (r"\$this->viewData",
     "Controller 没有 viewData 属性，模板靠局部变量作用域；这样改会丢功能"),
    (r"===\s*['\"]\*['\"]|Access-Control-Allow-Origin:\s*\*",
     "CORS 仍是通配 *"),
    (r"\b(md5|sha1)\s*\(\s*\\\$_(GET|POST|REQUEST|COOKIE)",
     "用 md5/sha1 直接吃用户输入做安全判断"),
]

EXT_LANG = {".php": "php", ".py": "python", ".js": "node", ".mjs": "node"}


def sh(argv):
    # 列表传参、不经 shell：文件名来自上传的源码包（可能含 " ; $() ` 等），
    # 用 shell=True 拼字符串会把文件名变成命令。
    p = subprocess.run(argv, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, errors="replace")
    return p.returncode, p.stdout.strip()


def syntax_check(path):
    lang = EXT_LANG.get(os.path.splitext(path)[1].lower())
    # 传绝对路径：以 - 开头的文件名不会被当成命令行开关
    path = os.path.abspath(path)
    if lang == "php":
        return sh(["php", "-l", path])
    if lang == "python":
        return sh(["python3", "-m", "py_compile", path])
    if lang == "node":
        return sh(["node", "--check", path])
    return 0, ""


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def newline_style(raw):
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n") - crlf
    return "CRLF" if crlf > lf else "LF"


def changed_lines(src_path, fix_path):
    a = read_bytes(src_path).decode("utf-8", "replace").splitlines()
    b = read_bytes(fix_path).decode("utf-8", "replace").splitlines()
    add = dele = 0
    for line in difflib.unified_diff(a, b, n=0, lineterm=""):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            add += 1
        elif line.startswith("-"):
            dele += 1
    return add, dele, len(a)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixed", default="fixed")
    ap.add_argument("--src", default="src")
    ap.add_argument("--strict", action="store_true",
                    help="未覆盖 critical/high 也判失败")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--max-ratio", type=float, default=0.5,
                    help="单文件改动行数占原文件比例上限，默认 0.5")
    args = ap.parse_args()

    errors, warns = [], []

    if not os.path.isdir(args.fixed):
        print("FAIL  %s/ 不存在 —— 本地 AI 根本没写文件，只在聊天里贴了代码" % args.fixed)
        return 2
    if not os.path.isdir(args.src):
        print("FAIL  找不到源码目录 %s/（请在 AI 修复包目录里运行）" % args.src)
        return 2

    files = []
    for root, _, names in os.walk(args.fixed):
        for n in sorted(names):
            files.append(os.path.join(root, n))
    if not files:
        print("FAIL  %s/ 是空的 —— 补丁会是空补丁" % args.fixed)
        return 2

    print("== 1. 路径与语法 ==")
    checked = []
    for fp in files:
        rel = os.path.relpath(fp, args.fixed)
        src_fp = os.path.join(args.src, rel)
        if not os.path.isfile(src_fp):
            if os.path.isdir(os.path.dirname(src_fp)):
                rc, out = syntax_check(fp)
                if rc != 0:
                    errors.append("语法错误（新增文件）：%s\n%s" % (rel, out))
                    print("  FAIL  %s  %s" % (rel, out.splitlines()[0] if out else "syntax"))
                    continue
                checked.append((rel, None, fp))
                print("  NEW   %s  （新增文件，父目录存在）" % rel)
                continue
            errors.append("路径对不上：%s 在 %s/ 里不存在，父目录也不存在（拼写错误？）"
                          % (rel, args.src))
            print("  FAIL  %s  ← src/ 里没有这个文件" % rel)
            continue
        rc, out = syntax_check(fp)
        if rc != 0:
            errors.append("语法错误：%s\n%s" % (rel, out))
            print("  FAIL  %s  %s" % (rel, out.splitlines()[0] if out else "syntax"))
            continue
        checked.append((rel, src_fp, fp))
        print("  OK    %s" % rel)

    print("\n== 2. 换行风格 / 改动规模 ==")
    for rel, src_fp, fp in checked:
        if src_fp is None:
            print("  OK    %s  （新增文件，无原文件可比）" % rel)
            continue
        s_style = newline_style(read_bytes(src_fp))
        f_style = newline_style(read_bytes(fp))
        if s_style != f_style:
            warns.append("换行风格变了：%s（原 %s，现 %s），diff 会整文件重写"
                         % (rel, s_style, f_style))
            print("  WARN  %s  换行 %s -> %s" % (rel, s_style, f_style))
        add, dele, total = changed_lines(src_fp, fp)
        ratio = (add + dele) / max(total, 1)
        flag = "WARN" if ratio > args.max_ratio else "OK  "
        print("  %s  %s  +%d/-%d 行（原 %d 行，%.0f%%）"
              % (flag, rel, add, dele, total, ratio * 100))
        if ratio > args.max_ratio:
            warns.append("改动过大：%s 改了 %.0f%%，像是整文件重写，review 不了"
                         % (rel, ratio * 100))

    print("\n== 3. 已知坏写法 ==")
    hit_any = False
    for rel, src_fp, fp in checked:
        text = read_bytes(fp).decode("utf-8", "replace")
        # unserialize 单独判：带 allowed_classes => false 是允许的
        for m in re.finditer(r"unserialize\s*\(([\s\S]{0,300}?)\)", text):
            if "allowed_classes" not in m.group(1):
                hit_any = True
                line_no = text[:m.start()].count("\n") + 1
                why = ("unserialize() 没加 ['allowed_classes' => false]，"
                       "魔术方法仍可被触发；改成 json_decode 更彻底")
                errors.append("坏写法：%s:%d  %s" % (rel, line_no, why))
                print("  FAIL  %s:%d  %s" % (rel, line_no, why))
                if args.verbose:
                    print("        %s" % text.splitlines()[line_no - 1].strip()[:110])
        # mkdir 吃到 realpath() 的返回值：目录不存在时 realpath 返回 false，mkdir 永不执行
        for v in set(re.findall(r"\$(\w+)\s*=\s*@?realpath\s*\(", text)):
            for m in re.finditer(r"mkdir\s*\(\s*\$%s\b" % re.escape(v), text):
                hit_any = True
                line_no = text[:m.start()].count("\n") + 1
                why = ("mkdir() 收到 realpath() 的返回值：目录不存在时 realpath 返回 false，"
                       "mkdir 永不执行，新建目录上传功能会坏；改成先 mkdir 再 realpath 校验")
                errors.append("坏写法：%s:%d  %s" % (rel, line_no, why))
                print("  FAIL  %s:%d  %s" % (rel, line_no, why))
                if args.verbose:
                    print("        %s" % text.splitlines()[line_no - 1].strip()[:110])
        for pat, why in BAD_PATTERNS:
            for m in re.finditer(pat, text, re.M):
                hit_any = True
                line_no = text[:m.start()].count("\n") + 1
                errors.append("坏写法：%s:%d  %s" % (rel, line_no, why))
                print("  FAIL  %s:%d  %s" % (rel, line_no, why))
                if args.verbose:
                    print("        %s" % text.splitlines()[line_no - 1].strip()[:110])
    if not hit_any:
        print("  OK    没命中已知坏写法")

    print("\n== 4. 覆盖率（对照 findings.json）==")
    findings = []
    fj = os.path.join(os.path.dirname(os.path.abspath(args.fixed)), "findings.json")
    if not os.path.isfile(fj):
        fj = "findings.json"
    if os.path.isfile(fj):
        findings = json.load(open(fj, encoding="utf-8")).get("findings", [])
    else:
        print("  SKIP  没找到 findings.json，跳过覆盖率检查")

    touched = {rel.replace(os.sep, "/") for rel, _, _ in checked}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    missing = []
    for f in findings:
        fpath = (f.get("file") or "").replace("\\", "/")
        if fpath not in touched:
            missing.append(f)
    if findings:
        by_sev = {}
        for f in missing:
            by_sev.setdefault(f.get("sev", "?"), []).append(f)
        for sev in ("critical", "high", "medium", "low"):
            items = by_sev.get(sev, [])
            if not items:
                print("  OK    %-8s 全部覆盖" % sev)
                continue
            mark = "FAIL " if sev in ("critical", "high") else "WARN "
            print("  %s %-8s 未覆盖 %d 条" % (mark, sev, len(items)))
            for f in items:
                print("        %s:%s  %s" % (f.get("file"), f.get("line"),
                                             f.get("name", "")))
            if sev in ("critical", "high"):
                errors.append("未覆盖 %d 条 %s 问题（见上）" % (len(items), sev))
            else:
                warns.append("未覆盖 %d 条 %s 问题" % (len(items), sev))

    print("\n" + "=" * 58)
    print("改动文件 %d 个，FAIL %d 条，WARN %d 条" % (len(checked), len(errors), len(warns)))
    hard = list(errors) + ([w for w in warns] if args.strict else [])
    if hard:
        print("\n先修掉下面这些再跑 make_patch.py：")
        for e in hard:
            print("  - " + e.replace("\n", "\n    "))
        return 1
    print("\n全部通过 —— 现在可以生成补丁：")
    print("  python3 make_patch.py %s/" % args.fixed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
