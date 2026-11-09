#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 AI 改好的文件转成 git apply / patch -p1 都能用的 unified diff，并自校验。

用法（在 AI 修复包目录里执行，即含 src/ 的那一层）：
    python3 make_patch.py fixed/                  # 对比 ./src 与 ./fixed，输出 fixes.patch
    python3 make_patch.py fixed/ -o my.patch      # 指定输出文件名
    python3 make_patch.py fixed/ --no-check       # 不跑 git apply 自校验
    python3 make_patch.py fixed/ --stat           # 只看改了哪些文件

fixed/ 里放「改好的完整文件」，目录结构与 src/ 完全一致，例如：
    fixed/qzone/deploy/app/controllers/AdminController.php

注意：这里要的是**整个文件**，不是 diff 片段。行号由本脚本算，AI 不用数。
"""
import argparse
import difflib
import os
import shutil
import subprocess
import sys
import tempfile

SKIP_DIRS = {"__pycache__", ".git", "node_modules", ".idea", ".vscode", ".DS_Store"}


def read_text(path):
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", "surrogateescape")


def to_lines(text):
    """保留原始换行符（CRLF 文件仍然是 CRLF）。"""
    return text.splitlines(keepends=True)


def walk(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in (".DS_Store",) or fn.endswith((".pyc", ".swp", "~")):
                continue
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace(os.sep, "/")
            out[rel] = fp
    return out


def emit(diff_lines):
    """difflib 输出的控制行补换行，内容行缺换行时补 \\ No newline 标记。"""
    buf = []
    for ln in diff_lines:
        if ln.startswith(("diff --git", "index ", "--- ", "+++ ", "@@")):
            buf.append(ln.rstrip("\r\n") + "\n")
        elif ln.endswith("\n"):
            buf.append(ln)
        else:
            buf.append(ln + "\n")
            buf.append("\\ No newline at end of file\n")
    return "".join(buf)


def strip_rel(rel, n):
    if n <= 0:
        return rel
    parts = rel.split("/")
    return "/".join(parts[n:]) if len(parts) > n else rel


def build_patch(src_root, new_root, allow_delete=False, strip=0):
    old = {strip_rel(k, strip): v for k, v in walk(src_root).items()}
    new = {strip_rel(k, strip): v for k, v in walk(new_root).items()}
    chunks = []
    changed = []
    for rel in sorted(new):
        b_text = read_text(new[rel])
        if rel in old:
            a_text = read_text(old[rel])
            if a_text == b_text:
                continue
            a_lines, b_lines = to_lines(a_text), to_lines(b_text)
            body = list(difflib.unified_diff(a_lines, b_lines,
                                             fromfile="a/" + rel, tofile="b/" + rel,
                                             n=3, lineterm=""))
            if not body:
                continue
            changed.append(("M", rel, len(a_lines), len(b_lines)))
        else:
            b_lines = to_lines(b_text)
            body = ["--- /dev/null\n", "+++ b/%s\n" % rel,
                    "@@ -0,0 +1,%d @@\n" % len(b_lines)] + ["+" + x for x in b_lines]
            changed.append(("A", rel, 0, len(b_lines)))
        chunks.append("diff --git a/%s b/%s\n" % (rel, rel))
        if rel not in old:
            chunks.append("new file mode 100644\n")   # git apply 靠这行识别新增文件
        chunks.append(emit(body))
    if not allow_delete:
        return "".join(chunks), changed
    for rel in sorted(set(old) - set(new)):
        a_lines = to_lines(read_text(old[rel]))
        body = ["--- a/%s\n" % rel, "+++ /dev/null\n",
                "@@ -1,%d +0,0 @@\n" % len(a_lines)] + ["-" + x for x in a_lines]
        chunks.append("diff --git a/%s b/%s\n" % (rel, rel))
        chunks.append("deleted file mode 100644\n")
        chunks.append(emit(body))
        changed.append(("D", rel, len(a_lines), 0))
    return "".join(chunks), changed


def self_check(src_root, patch_text, strip=0):
    """在临时副本里 git init + commit + git apply --check，权威验证 patch 可用。"""
    if not shutil.which("git"):
        return None, "未找到 git，跳过自校验"
    tmp = tempfile.mkdtemp(prefix="mp-check-")
    try:
        work = os.path.join(tmp, "w")
        shutil.copytree(src_root, work)
        for _ in range(strip):          # 校验时按同样的层级裁剪
            sub = os.listdir(work)
            if len(sub) == 1 and os.path.isdir(os.path.join(work, sub[0])):
                inner = os.path.join(work, sub[0])
                for name in os.listdir(inner):
                    shutil.move(os.path.join(inner, name), os.path.join(work, name))
                os.rmdir(inner)
            else:
                break
        env = dict(os.environ, GIT_AUTHOR_NAME="mp", GIT_AUTHOR_EMAIL="mp@local",
                   GIT_COMMITTER_NAME="mp", GIT_COMMITTER_EMAIL="mp@local")
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "commit", "-qm", "base", "--allow-empty"]):
            subprocess.run(cmd, cwd=work, env=env, capture_output=True)
        pf = os.path.join(tmp, "p.patch")
        with open(pf, "w", encoding="utf-8", newline="") as fh:
            fh.write(patch_text)
        r = subprocess.run(["git", "apply", "--check", "-p1", pf],
                           cwd=work, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            return False, (r.stderr or r.stdout).strip()
        return True, "git apply --check 通过"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def apply_to(target, patch_text):
    """把 patch 应用到真实项目目录，自动探测层级（-p1..-p6），返回 (ok, p, msg)。"""
    if not os.path.isdir(target):
        return False, 0, "目标目录不存在: %s" % target
    tmp = tempfile.mkdtemp(prefix="mp-apply-")
    try:
        pf = os.path.join(tmp, "p.patch")
        with open(pf, "w", encoding="utf-8", newline="") as fh:
            fh.write(patch_text)
        last = ""
        for pnum in range(1, 7):
            chk = subprocess.run(["git", "apply", "--check", "-p%d" % pnum, pf],
                                 cwd=target, capture_output=True, text=True)
            if chk.returncode != 0:
                last = (chk.stderr or chk.stdout).strip()
                continue
            real = subprocess.run(["git", "apply", "-p%d" % pnum, pf],
                                  cwd=target, capture_output=True, text=True)
            if real.returncode == 0:
                return True, pnum, "已应用到 %s（-p%d）" % (target, pnum)
            last = (real.stderr or real.stdout).strip()
        return False, 0, "在 %s 里试了 -p1..-p6 都应用不了：\n%s" % (target, last)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("fixed", help="放改好文件的目录（结构与 src/ 一致）")
    ap.add_argument("-s", "--src", default="src", help="原始源码目录，默认 ./src")
    ap.add_argument("-o", "--out", default=None, help="输出 patch 文件名")
    ap.add_argument("--no-check", action="store_true", help="跳过 git apply 自校验")
    ap.add_argument("--stat", action="store_true", help="只打印改动统计")
    ap.add_argument("--apply-to", default=None, metavar="DIR",
                    help="生成后直接应用到真实项目目录，自动探测 -p 层级（推荐）")
    ap.add_argument("--strip", type=int, default=0, metavar="N",
                    help="生成 patch 时去掉路径前 N 层（zip 里带 qzone/ 这种顶层目录时用 1）")
    ap.add_argument("--allow-delete", action="store_true",
                    help="把「src 有、fixed 没有」的文件当成删除（默认忽略，防止 AI 只输出部分文件时误删）")
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        sys.exit("找不到源码目录: %s（请在 AI 修复包目录里运行）" % args.src)
    if not os.path.isdir(args.fixed):
        sys.exit("找不到改好的目录: %s" % args.fixed)

    patch, changed = build_patch(args.src, args.fixed, args.allow_delete, args.strip)
    if not changed:
        sys.exit("没有任何改动（fixed/ 与 src/ 内容一致）")

    total = len(walk(args.src))
    missing = total - len(walk(args.fixed))
    if missing > 0 and not args.allow_delete:
        print("提示：src/ 有 %d 个文件、%s 里只有 %d 个 —— 未出现的 %d 个按「没改」处理，不会被删除。"
              % (total, args.fixed, len(walk(args.fixed)), missing))
        print("      （如果确实要删文件，加 --allow-delete）\n")
    tops = {k.split("/")[0] for k in walk(args.fixed)}
    if args.strip == 0 and len(tops) == 1 and all("/" in k for k in walk(args.fixed)):
        print("提示：路径都带顶层目录 `%s/`。如果项目根目录就是 %s/ 里面，"
              "加 --strip 1 生成更短的路径。" % (list(tops)[0], list(tops)[0]))
    print("改动文件 %d 个：" % len(changed))
    for flag, rel, a, b in changed:
        print("  %s %-60s %d -> %d 行" % (flag, rel, a, b))
    if args.stat:
        return

    out = args.out or "fixes.patch"
    with open(out, "w", encoding="utf-8", newline="") as fh:
        fh.write(patch)
    print("\n已生成: %s  (%d 字节)" % (out, len(patch.encode("utf-8"))))

    if args.no_check and not args.apply_to:
        return
    ok, msg = (True, "已跳过") if args.no_check else self_check(args.src, patch, args.strip)
    if ok is None:
        print("[跳过] %s" % msg)
    elif ok:
        print("[通过] %s" % msg)
        print("\n应用到真实项目（在项目根目录执行，git apply 会自动识别层级）：")
        print("  git apply %s" % os.path.abspath(out))
        print("  或   patch -p1 < %s" % os.path.abspath(out))
    else:
        print("[失败] patch 不能应用：\n%s" % msg)
        sys.exit(1)

    if args.apply_to:
        aok, pnum, amsg = apply_to(os.path.abspath(args.apply_to), patch)
        print(("\n[已应用] %s" if aok else "\n[应用失败] %s") % amsg)
        if not aok:
            sys.exit(1)
        print("回滚：cd %s && git apply -R -p%d %s"
              % (os.path.abspath(args.apply_to), pnum, os.path.abspath(out)))


if __name__ == "__main__":
    main()
