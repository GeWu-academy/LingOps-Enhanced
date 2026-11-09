#!/usr/bin/env python3
"""把 ARTEX 的管理员账号名从 ARTEX 改成 admin（界面 + 接口全链路）。

ARTEX 的账号名 `ARTEX` 一共出现在三个地方，全部要改：

1. 后端登录校验：编译器把它内联成了 3 条 ARM64 立即数指令（不是字符串常量，
   所以全文替换 ARTEX 无效）：
       cmp  x4, #0x5                    长度必须是 5
       mov  x5, #0x5241                 'A','R'
       movk x5, #0x4554, lsl #16        'T','E'   -> x5 = "ARTE"
       cmp  w4, w5
       ldrb w3, [x3, #0x4]
       cmp  w3, #0x58                   'X'
   即文件偏移 10764696 / 10764700 / 10764716 三个 32 位小端字。
2. 前端登录：静态 JS 里的 api.login("ARTEX", 密码)。
3. JWT sub：登录成功后界面显示的账号名（文件偏移 11953048 的 5 字节常量）。

macOS(arm64) 上改完必须重签名，否则进程会被直接 SIGKILL（日志为空）。

用法：
    python3 patch-artex-admin.py            # 改成 admin
    python3 patch-artex-admin.py bob        # 改成任意 5 字符名字
    python3 patch-artex-admin.py --revert   # 全部改回 ARTEX
"""
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "artex", "artex")
ORIG = b"ARTEX"

OFF_SUB = 11953048                      # JWT sub 常量
OFF_CMP = [10764696, 10764700, 10764716]  # movz / movk / cmp


def encode_imm(name: bytes):
    """把 5 字节名字编码成登录校验那三条指令的新字面值。"""
    word4 = int.from_bytes(name[:4], "little")
    lo, hi, b5 = word4 & 0xFFFF, (word4 >> 16) & 0xFFFF, name[4]
    return [
        0xD2800000 | (lo << 5) | 5,               # movz x5, #lo
        0xF2800000 | (1 << 21) | (hi << 5) | 5,   # movk x5, #hi, lsl #16
        0x71000000 | (b5 << 10) | (3 << 5) | 31,  # cmp  w3, #b5
    ]


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--revert"]
    revert = "--revert" in sys.argv[1:]
    name = ORIG if revert else (args[0] if args else "admin")

    if isinstance(name, str):
        name = name.encode()
    if len(name) != len(ORIG):
        print(f"[错误] 名字必须正好 {len(ORIG)} 个字节（ASCII），收到 {name!r}")
        return 1
    if not os.path.exists(BIN):
        print(f"[错误] 找不到 {BIN}（这个包是 darwin 版才有 artex/）")
        return 1

    data = bytearray(open(BIN, "rb").read())
    changed = []

    cur = bytes(data[OFF_SUB:OFF_SUB + 5])
    if not re.fullmatch(rb"[A-Za-z]{5}", cur):
        print(f"[错误] 偏移 {OFF_SUB} 处不是 5 字母账号名（实际 {cur!r}）。")
        print("       换新版二进制后偏移会变，重新定位 5 字节的 'ARTEX' 再改本脚本。")
        return 1
    if cur != name:
        data[OFF_SUB:OFF_SUB + 5] = name
        changed.append(f"JWT sub  偏移 {OFF_SUB}: {cur.decode()} -> {name.decode()}")

    for off, new_word in zip(OFF_CMP, encode_imm(name)):
        old_word = struct.unpack("<I", bytes(data[off:off + 4]))[0]
        if old_word == new_word:
            continue
        data[off:off + 4] = struct.pack("<I", new_word)
        changed.append(f"登录校验 偏移 {off}: {old_word:#010x} -> {new_word:#010x}")

    m = re.search(rb'api\.login\("([A-Za-z]{5})"', bytes(data))
    if m and m.group(1) != name:
        i = m.start(1)
        data[i:i + 5] = name
        changed.append(f"前端登录 偏移 {i}: {m.group(1).decode()} -> {name.decode()}")

    if not changed:
        print(f"[跳过] 已经是 {name.decode()}")
        return 0

    shutil.copy2(BIN, BIN + ".bak")
    open(BIN, "wb").write(bytes(data))
    os.chmod(BIN, 0o755)
    for line in changed:
        print("[改写] " + line)

    if sys.platform == "darwin":
        r = subprocess.run(["codesign", "-s", "-", "-f", BIN],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("[警告] codesign 失败，ARTEX 会被系统直接杀掉：")
            print(r.stderr.strip())
            return 1
        print("[签名] ad-hoc 重签名完成")
    print("完成。重启生效： ./stop.sh && ./start.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
