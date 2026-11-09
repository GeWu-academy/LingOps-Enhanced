#!/usr/bin/env python3
"""AWDP Break/Fix 内容库：在 data/poc/*.json（随包发布的种子）与 data/lingops.db（运行时库）之间同步。

用法：
  awdp_lib.py export            # 数据库 → data/poc/*.json
  awdp_lib.py import            # data/poc/*.json → 数据库（幂等，按主键 upsert）
  awdp_lib.py sync  <extra...>  # 合并扩充文件 → JSON 种子，并写入数据库
  awdp_lib.py stats             # 打印各表条目数

扩充文件格式（一个 JSON，可含任意子集）：
  {"payloads":[...], "exploits":[...], "bypasses":[...], "knowledge":[...], "rules":[...]}

knowledge / rules 里的数组字段（danger_functions / code_patterns / input_sources /
match_rules / bypass_methods / tags / references）可以写成真正的数组，脚本会自动 JSON 编码。
"""
import argparse, datetime, json, os, sqlite3, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB = os.path.join(ROOT, "data", "lingops.db")
POC = os.path.join(ROOT, "data", "poc")

BREAK_COLS = {
    "payloads": ["item_id", "title", "language", "category", "description", "body"],
    "exploits": ["item_id", "title", "language", "description", "body"],
    "bypasses": ["item_id", "title", "target", "description", "body"],
}
BREAK_TABLE = {"payloads": "break_payloads", "exploits": "break_exploits", "bypasses": "break_bypasses"}

KB_COLS = [
    "name", "category", "language", "framework", "severity", "description",
    "danger_functions", "code_patterns", "input_sources", "match_rules",
    "fix_fast_method", "fix_secure_method", "fix_code_example", "fix_code_language",
    "fix_summary", "exploit_tip", "waf_template", "waf_dependencies", "whitelist_rule",
    "blacklist_rule", "framework_fix", "bypass_methods", "false_positive", "tags",
    "references", "source_type", "is_builtin", "is_active",
]
RULE_COLS = [
    "name", "rule_id", "language", "framework", "category", "severity", "confidence",
    "description", "type", "pattern", "exclude_pattern", "priority", "fix_suggestion",
    "template_id", "source_type", "hit_count_total", "is_builtin", "is_active",
]
JSON_FIELDS = {
    "danger_functions", "code_patterns", "input_sources", "match_rules",
    "bypass_methods", "tags", "references",
}
NOW = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime(
    "%Y-%m-%d %H:%M:%S+08:00")


def Q(cols):
    """SQL 标识符加引号（references 等是 SQL 关键字）。"""
    return ",".join('"%s"' % c for c in cols)


def _norm(row, cols):
    out = {}
    for c in cols:
        v = row.get(c)
        if c in JSON_FIELDS and isinstance(v, (list, dict)):
            v = json.dumps(v, ensure_ascii=False)
        out[c] = v
    return out


def connect(db=DB):
    con = sqlite3.connect(db, timeout=20)
    con.execute("pragma busy_timeout=20000")
    return con


def upsert_break(con, kind, items):
    table, cols = BREAK_TABLE[kind], BREAK_COLS[kind]
    n = 0
    for it in items:
        it = dict(it)
        it.setdefault("item_id", it.get("id"))
        row = _norm(it, cols)
        row["is_builtin"] = 1
        names = list(row.keys())
        ph = ",".join("?" * len(names))
        sets = ",".join('"%s"=excluded."%s"' % (c, c) for c in names if c != "item_id")
        con.execute(
            "insert into %s (created_at,updated_at,%s) values (?,?,%s) "
            "on conflict(item_id) do update set updated_at=?,%s"
            % (table, Q(names), ph, sets),
            [NOW, NOW] + [row[c] for c in names] + [NOW],
        )
        n += 1
    return n


def upsert_knowledge(con, items):
    n = 0
    for it in items:
        row = _norm(it, KB_COLS)
        row.setdefault("source_type", "builtin")
        row["is_builtin"] = 1
        row["is_active"] = row.get("is_active") if row.get("is_active") is not None else 1
        cur = con.execute("select id from vulnerability_templates where name=?", (row["name"],))
        hit = cur.fetchone()
        names = list(row.keys())
        if hit:
            sets = ",".join('"%s"=?' % c for c in names)
            con.execute("update vulnerability_templates set %s, updated_at=? where id=?" % sets,
                        [row[c] for c in names] + [NOW, hit[0]])
            tid = hit[0]
        else:
            ph = ",".join("?" * len(names))
            cur = con.execute(
                "insert into vulnerability_templates (created_at,updated_at,%s) values (?,?,%s)"
                % (Q(names), ph), [NOW, NOW] + [row[c] for c in names])
            tid = cur.lastrowid
        # 模板内嵌的 match_rules 一并落成独立扫描规则
        mr = row.get("match_rules")
        if mr:
            try:
                rules = json.loads(mr) if isinstance(mr, str) else mr
            except Exception:
                rules = []
            for r in rules:
                r = dict(r)
                r.setdefault("language", row["language"])
                r.setdefault("category", row["category"])
                r.setdefault("severity", row["severity"])
                r.setdefault("template_id", tid)
                r.setdefault("fix_suggestion", row.get("fix_secure_method") or row.get("fix_summary") or "")
                if r.get("rule_id"):
                    upsert_rules(con, [r])
        n += 1
    return n


def upsert_rules(con, items):
    n = 0
    for it in items:
        row = _norm(it, RULE_COLS)
        row.setdefault("type", "regex")
        row.setdefault("confidence", "medium")
        row.setdefault("priority", 5)
        row.setdefault("framework", "")
        row.setdefault("source_type", "builtin")
        row.setdefault("template_id", 0)
        row.setdefault("hit_count_total", 0)
        row["is_builtin"] = 1
        row["is_active"] = 1
        if not row.get("rule_id") or not row.get("pattern"):
            continue
        names = list(row.keys())
        sets = ",".join('"%s"=excluded."%s"' % (c, c) for c in names if c != "rule_id")
        ph = ",".join("?" * len(names))
        con.execute(
            "insert into vulnerability_scan_rules (created_at,updated_at,%s) values (?,?,%s) "
            "on conflict(rule_id) do update set updated_at=?,%s"
            % (Q(names), ph, sets),
            [NOW, NOW] + [row[c] for c in names] + [NOW],
        )
        n += 1
    return n


def apply(con, data):
    got = {}
    for kind in ("payloads", "exploits", "bypasses"):
        if data.get(kind):
            got[kind] = upsert_break(con, kind, data[kind])
    if data.get("knowledge"):
        got["knowledge"] = upsert_knowledge(con, data["knowledge"])
    if data.get("rules"):
        got["rules"] = upsert_rules(con, data["rules"])
    return got


KIND_HINTS = (("payload", "payloads"), ("exploit", "exploits"), ("bypass", "bypasses"),
              ("knowledge", "knowledge"), ("rule", "rules"))


def _guess_kind(path):
    """顶层是数组时按文件名猜类型：01-payloads-php.json / 07-knowledge-*.json / 10-rules.json"""
    name = os.path.basename(path).lower()
    for hint, kind in KIND_HINTS:
        if hint in name:
            return kind
    return None


def load_extra(paths):
    merged = {}
    for p in paths:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, list):
            kind = _guess_kind(p)
            if not kind:
                sys.exit("无法从文件名判断类型：%s（请用 {\"%s\": [...]} 包裹）" % (p, "payloads"))
            merged.setdefault(kind, []).extend(d)
            continue
        for k, v in d.items():
            if isinstance(v, list):
                merged.setdefault(k, []).extend(v)
    return merged


def export(con, out=POC):
    os.makedirs(out, exist_ok=True)
    bcols = ["item_id", "title", "language", "category", "description", "body"]
    payloads = [dict(zip(("id", "title", "language", "category", "description", "body"), r))
                for r in con.execute(
        "select item_id,title,language,category,description,body from break_payloads order by id")]
    exploits = [dict(zip(("id", "title", "language", "description", "body"), r)) for r in con.execute(
        "select item_id,title,language,description,body from break_exploits order by id")]
    bypasses = [dict(zip(("id", "title", "target", "description", "body"), r)) for r in con.execute(
        "select item_id,title,target,description,body from break_bypasses order by id")]
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    with open(os.path.join(out, "break-library.json"), "w", encoding="utf-8") as f:
        json.dump({"version": "1.1.0", "exported_at": stamp, "payloads": payloads,
                   "exploits": exploits, "bypasses": bypasses}, f, ensure_ascii=False, indent=1)

    kcols = ["id", "created_at", "updated_at"] + KB_COLS
    knowledge = [dict(zip(kcols, r)) for r in con.execute(
        "select id,created_at,updated_at,%s from vulnerability_templates order by id" % Q(KB_COLS))]
    rcols = ["id", "created_at", "updated_at"] + RULE_COLS
    rules = [dict(zip(rcols, r)) for r in con.execute(
        "select id,created_at,updated_at,%s from vulnerability_scan_rules order by id" % Q(RULE_COLS))]
    with open(os.path.join(out, "fix-library.json"), "w", encoding="utf-8") as f:
        json.dump({"version": "1.1.0", "exported_at": stamp, "knowledge": knowledge,
                   "rules": rules}, f, ensure_ascii=False, indent=1)
    return len(payloads), len(exploits), len(bypasses), len(knowledge), len(rules)


def import_json(con, src=POC):
    total = {}
    for name, kind in (("break-library.json", None), ("fix-library.json", None)):
        with open(os.path.join(src, name), encoding="utf-8") as f:
            d = json.load(f)
        for k in ("payloads", "exploits", "bypasses"):
            if d.get(k):
                for it in d[k]:
                    it["item_id"] = it.get("item_id") or it.get("id")
        got = apply(con, d)
        for k, v in got.items():
            total[k] = total.get(k, 0) + v
    return total


def stats(con):
    out = {}
    for t in ("break_payloads", "break_exploits", "break_bypasses",
              "vulnerability_templates", "vulnerability_scan_rules"):
        out[t] = con.execute("select count(*) from %s" % t).fetchone()[0]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["export", "import", "sync", "stats"])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--db", default=DB)
    ap.add_argument("--out", default=POC)
    a = ap.parse_args()
    con = connect(a.db)
    try:
        if a.cmd == "export":
            print("export:", export(con, a.out))
        elif a.cmd == "import":
            print("import:", import_json(con, a.out))
            con.commit()
        elif a.cmd == "sync":
            if not a.files:
                sys.exit("sync 需要至少一个扩充 JSON")
            got = apply(con, load_extra(a.files))
            con.commit()
            print("db upsert:", got)
            print("export:", export(con, a.out))
        else:
            print(json.dumps(stats(con), ensure_ascii=False, indent=1))
    finally:
        con.close()


if __name__ == "__main__":
    main()
