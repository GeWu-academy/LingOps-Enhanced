#!/usr/bin/env python3
"""重打两个发布 zip（darwin-arm64 / win64）。

做法：以上一版 zip 的条目清单为基准，只刷新文件内容；再补 EXTRA_DIRS / EXTRA_FILES。
这样官方二进制、目录结构不会意外漂移。

发布包排除清单见 DROP_REL / DROP_PREFIX / DROP_SUFFIX —— 旧 zip 清单里带着
artex/config.json（本机明文数据库口令）等运行态文件，只按「磁盘上存在」判断
会把它们一起发出去，所以必须有这一层显式过滤。

注意：不要用 .gitignore 当发布过滤条件。它把 frontend/dist 官方产物也忽略了
（只白名单了 assets_v2/lp-ext/），按 gitignore 过滤会把整个前端和 win64 的
便携 Python 剔掉，包直接不能用。

用法：python3 ext/tools/build_release.py
前置：BASE 下要有上一版的 zip（旧清单来源），WIN_EXTRA 目录要准备好。
"""
import os, sys, zipfile, time

BASE = "/Users/shu/ctf/ctf工具包"
INSTALL = os.path.join(BASE, "LingOps_v0.2_darwin_arm64")

VER = "v1.3.8"

JOBS = [
    # (old zip, new zip, root in zip, take-from-disk)
    ("LingOps_v0.2_darwin_arm64-enhanced.zip",
     "LingOps-AWD-AWDP-Enhanced-%s-darwin-arm64.zip" % VER,
     "LingOps-AWD-AWDP-Enhanced-%s-darwin-arm64" % VER, True),
    ("LingOps_v0.2_win64_enhanced.zip",
     "LingOps-AWD-AWDP-Enhanced-%s-win64.zip" % VER,
     "LingOps-AWD-AWDP-Enhanced-%s-win64" % VER, False),
]

# 发布包排除清单（相对包根）。旧 zip 的清单里带着这些文件，只按「磁盘上存在」判断
# 会把本机运行态一起发出去 —— artex/config.json 里就有明文数据库口令。
DROP_REL = {
    "artex/config.json",      # 本机 PostgreSQL 口令，只该发 config.example.json
    "artex/jwt.key",          # artex 签名密钥
    "data/lingops.db",        # 资产/凭据/口令哈希，含真实扫描记录
}
DROP_PREFIX = (
    "artex/data/",            # MITM CA 私钥等运行态
    "tests/awdp-corpus/corpus/",  # 故意埋洞的回归语料，发布包不带（见 README 说明）
    ".cache/",
    ".git/",
)
DROP_SUFFIX = (".db", ".db-wal", ".db-shm", ".pem", ".key", ".p12", ".pfx")
DROP_NAME = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials.json"}


def skip_rel(rel):
    """True = 不进发布包。显式清单 + gitignore 双保险。"""
    if rel in DROP_REL:
        return True
    if any(rel.startswith(p) for p in DROP_PREFIX):
        return True
    if rel.endswith(DROP_SUFFIX):
        return True
    if os.path.basename(rel) in DROP_NAME:
        return True
    return False



# files that only exist in the win64 package and must be carried over verbatim
WIN_ONLY = {"lingops-server.exe", "start.bat", "stop.bat"}

# win64 专用覆盖层：包内便携版 Python + 改过的 start.bat（相对包根，按目录树覆盖/新增）
WIN_EXTRA = "/tmp/lpzip/win-extra"

# 新增目录：旧 zip 清单里没有，直接从 INSTALL 补齐（平台无关的测试语料/文档）
EXTRA_DIRS = ["tests", "ext/tools"]
# 新增的根目录文件（旧 zip 清单里没有）
EXTRA_FILES = ["CHANGELOG.md", "README.md", ".gitignore"]
SKIP_PARTS = {"__pycache__", ".git", ".DS_Store", "node_modules"}


def build(old, new, root, from_disk_always, extra_dir=None):
    oldp = os.path.join(BASE, old)
    src = zipfile.ZipFile(oldp)
    # 旧 zip 的根目录可能和新包名不同，剥离前缀必须用旧根目录
    _names = [i.filename for i in src.infolist() if not i.is_dir()]
    old_root = _names[0].split("/")[0] if _names else root
    # 磁盘上已删除的文件不能从旧 zip 里「搬回来」（否则删掉的功能会复活）
    entries = [i.filename for i in src.infolist()
               if not i.is_dir()
               and not skip_rel(i.filename[len(old_root) + 1:])
               and (os.path.isfile(os.path.join(INSTALL, i.filename[len(old_root) + 1:]))
                    or os.path.basename(i.filename) in WIN_ONLY)]
    # 去重集合统一用「相对包根」的路径，避免新旧根目录名不同导致重复条目
    have = set(e[len(old_root) + 1:] if e.startswith(old_root + "/") else e[len(root) + 1:]
               for e in entries)
    for d in EXTRA_DIRS:
        base = os.path.join(INSTALL, d)
        for dp, dns, fns in os.walk(base):
            dns[:] = [x for x in dns if x not in SKIP_PARTS]
            for fn in fns:
                if fn in SKIP_PARTS or fn.endswith(".pyc"):
                    continue
                rel = os.path.relpath(os.path.join(dp, fn), INSTALL)
                rel = rel.replace(os.sep, "/")
                if skip_rel(rel):
                    continue
                if rel not in have:
                    have.add(rel)
                    entries.append(root + "/" + rel)

    extra = {}
    if extra_dir:
        for dp, dns, fns in os.walk(extra_dir):
            dns[:] = [x for x in dns if x not in SKIP_PARTS]
            for fn in fns:
                if fn in SKIP_PARTS or fn.endswith(".pyc"):
                    continue
                full = os.path.join(dp, fn)
                rel = os.path.relpath(full, extra_dir).replace(os.sep, "/")
                if skip_rel(rel):
                    continue
                extra[rel] = full
                if rel not in have:
                    have.add(rel)
                    entries.append(root + "/" + rel)

    for fn in EXTRA_FILES:
        if fn not in have and not skip_rel(fn) and os.path.isfile(os.path.join(INSTALL, fn)):
            have.add(fn)
            entries.append(root + "/" + fn)

    # 注意：不能用 .gitignore 当发布过滤条件 —— 它把 frontend/dist 官方产物也忽略了
    # （只白名单了 lp-ext/），按 gitignore 过滤会把整个前端和 win64 的便携 Python 剔掉。
    # 所以只用上面的 DROP_* 显式清单。

    tmp = os.path.join("/tmp/lpzip", new + ".tmp")
    written, carried = 0, 0
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for name in sorted(entries):
            # 旧条目带旧根目录，新条目（EXTRA_DIRS/EXTRA_FILES/WIN_EXTRA）已带新根目录
            if name.startswith(old_root + "/"):
                rel = name[len(old_root) + 1:]
            else:
                rel = name[len(root) + 1:]
            name = root + "/" + rel
            disk = extra.get(rel) or os.path.join(INSTALL, rel)
            use_disk = os.path.isfile(disk) and (
                rel in extra or from_disk_always or os.path.basename(rel) not in WIN_ONLY)
            if use_disk:
                data = open(disk, "rb").read()
            else:
                data = src.read(old_root + "/" + rel)
                carried += 1
            zi = zipfile.ZipInfo(name, date_time=time.localtime(os.path.getmtime(disk))[:6]
                                 if use_disk else time.localtime()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if (rel.endswith(".sh") or rel in ("lingops-server", "lingops-server.exe", "artex/artex")) else 0o644
            zi.external_attr = (mode & 0xFFFF) << 16
            out.writestr(zi, data)
            written += 1
    src.close()

    with zipfile.ZipFile(tmp) as z:
        assert z.testzip() is None, "corrupt zip"
        n = len([i for i in z.infolist() if not i.is_dir()])
        assert n == len(entries), "entry count changed: %d != %d" % (n, len(entries))
    final = os.path.join(BASE, new)
    os.replace(tmp, final)
    print("  %-38s %2d files  %10d B  (carried over: %d)"
          % (new, written, os.path.getsize(final), carried))
    return final


print("[*] rebuilding")
for old, new, root, fd in JOBS:
    build(old, new, root, fd, WIN_EXTRA if not fd else None)
print("[+] done")
