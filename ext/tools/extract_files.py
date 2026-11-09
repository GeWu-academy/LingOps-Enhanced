#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 AI 聊天回复里带 === FILE: xxx === 标记的代码块，拆成 fixed/ 下的真实文件。

用法（在 AI 修复包目录里执行，即含 src/ 的那一层）：
    # 1) 把 AI 的整段回复原样存成 ai.txt（或直接从剪贴板读）
    pbpaste > ai.txt          # macOS
    # xclip -o > ai.txt       # Linux
    # 手动复制粘贴到 ai.txt

    # 2) 拆分
    python3 extract_files.py ai.txt            # 默认写到 fixed/
    python3 extract_files.py ai.txt -o fixed2  # 指定输出目录
    python3 extract_files.py --stdin           # 直接从标准输入读

    # 3) 生成 patch
    python3 make_patch.py fixed/

支持的标记（大小写、空格、===== 数量都无所谓）：
    === FILE: qzone/deploy/app/controllers/AdminController.php ===
    ...文件完整内容...
    === END FILE ===

也兼容这些写法：
    ### FILE: path
    ```php:path/to/file.php
    // FILE: path/to/file.php
"""
import argparse
import os
import re
import sys

# === FILE: path ===  /  ### FILE: path  /  // FILE: path  /  <!-- FILE: path -->
_LEAD = r"^[ \t]*(?:={2,}|#{2,}|//+|--|;|<!--)"
_TAIL = r"[ \t]*(?:-->|={2,}|#{2,}|\*\*/)?[ \t]*$"
RE_FILE = re.compile(
    _LEAD + r"[ \t]*FILE[ \t]*:[ \t]*(?P<p>[^\s*>]+)" + _TAIL, re.I)
RE_END = re.compile(_LEAD + r"[ \t]*END[ \t]*FILE" + _TAIL, re.I)
# ```php:path/to/file.php  或  ```path/to/file.php
RE_FENCE_PATH = re.compile(r"^[ \t]*```[a-zA-Z0-9_+-]*[ \t]*:[ \t]*(?P<p>[^\s`]+)[ \t]*$")
RE_FENCE = re.compile(r"^[ \t]*```")


def clean_path(p):
    p = p.strip().strip("'\"`").replace("\\", "/")
    for pre in ("./", "src/", "fixed/"):
        if p.startswith(pre):
            p = p[len(pre):]
    p = p.lstrip("/")
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def parse(text):
    """返回 [(相对路径, 内容)]。同一路径出现多次时后者覆盖前者。"""
    lines = text.splitlines()
    out = {}
    order = []
    cur = None
    buf = []
    fence = False          # 是否处于 ``` 代码块内
    started_by_fence = False

    def flush():
        nonlocal cur, buf
        if cur is not None:
            body = "\n".join(buf).strip("\n")
            if body.strip():
                out[cur] = body + "\n"
                if cur not in order:
                    order.append(cur)
        cur, buf = None, []

    for ln in lines:
        m = RE_FILE.match(ln) or RE_FENCE_PATH.match(ln)
        if m and cur is None:
            p = clean_path(m.group("p"))
            if p:
                cur, buf = p, []
                started_by_fence = bool(RE_FENCE_PATH.match(ln))
                fence = started_by_fence
                continue
        if cur is not None:
            if RE_END.match(ln):
                flush()
                fence, started_by_fence = False, False
                continue
            if RE_FENCE.match(ln):
                if started_by_fence and not fence:
                    fence = True
                    continue
                if fence:
                    flush()
                    fence, started_by_fence = False, False
                    continue
            buf.append(ln)
            continue
    flush()
    return [(p, out[p]) for p in order]


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("file", nargs="?", help="AI 回复保存的文本文件")
    ap.add_argument("-o", "--out", default="fixed", help="输出目录，默认 ./fixed")
    ap.add_argument("--stdin", action="store_true", help="从标准输入读取")
    ap.add_argument("--src", default="src", help="原始源码目录（用于校验路径是否存在），默认 ./src")
    ap.add_argument("--force", action="store_true", help="路径在 src/ 里找不到时也照写")
    ap.add_argument("--list", action="store_true", help="只列出解析到的文件，不写盘")
    args = ap.parse_args()

    if args.stdin or not args.file:
        text = sys.stdin.read()
    else:
        with open(args.file, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    if not text.strip():
        sys.exit("没有输入内容")

    files = parse(text)
    if not files:
        sys.exit("没解析到任何文件。请让 AI 用这个格式输出：\n"
                 "=== FILE: 相对路径 ===\n<完整文件内容>\n=== END FILE ===")

    if args.list:
        for p, body in files:
            print("%-62s %d 行" % (p, body.count("\n")))
        return

    src_ok = os.path.isdir(args.src)
    written, warned = 0, 0
    for rel, body in files:
        srcp = os.path.join(args.src, rel)
        if src_ok and not os.path.isfile(srcp) and not args.force:
            print("[跳过] %s —— src/ 里没有这个文件（确认路径，或加 --force）" % rel)
            warned += 1
            continue
        dst = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        # 跟随原文件的换行风格，避免整文件 diff
        if os.path.isfile(srcp):
            with open(srcp, "rb") as fh:
                if b"\r\n" in fh.read(4096):
                    body = body.replace("\r\n", "\n").replace("\n", "\r\n")
        with open(dst, "w", encoding="utf-8", newline="") as fh:
            fh.write(body)
        written += 1
        print("[写入] %s  (%d 行)" % (dst, body.count("\n")))

    print("\n共 %d 个文件写入 %s/，跳过 %d 个。" % (written, args.out, warned))
    if written:
        print("\n下一步：python3 make_patch.py %s/" % args.out)
        if not src_ok:
            print("提示：当前目录没有 src/，make_patch.py 需要它来算 diff。")


if __name__ == "__main__":
    main()
