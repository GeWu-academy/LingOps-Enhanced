#!/usr/bin/env python3
"""
extract_route_map.py <JSDIR> <OUTDIR>

Scan downloaded JS chunks for routeMap / routeLink style objects:
  KEY:{name:"...",link:"/path"}

Writes route_map.json — used by build_perm_tree.py to resolve alias refs.
"""
import re, json, os, sys, glob

_HOME = os.path.expanduser('~')
FORBIDDEN_ROOTS = ('/etc', '/usr', '/bin', '/sbin', '/boot', '/dev', '/proc', '/sys', '/root',
                   '/System', '/Library/LaunchDaemons', '/Library/LaunchAgents', '/var/root',
                   os.path.join(_HOME, '.ssh'), os.path.join(_HOME, '.aws'),
                   os.path.join(_HOME, '.gnupg'), os.path.join(_HOME, '.config', 'autostart'),
                   os.path.join(_HOME, 'Library', 'LaunchAgents'), os.path.join(_HOME, 'Library', 'LaunchDaemons'))

def safe_outdir(p):
    """Normalize the output dir; refuse NUL bytes and system/persistence dirs."""
    if not isinstance(p, str) or not p.strip() or '\x00' in p:
        sys.exit('[!] invalid output dir')
    ap = os.path.realpath(os.path.abspath(os.path.expanduser(p)))
    for root in FORBIDDEN_ROOTS:
        root = os.path.realpath(root)
        if ap == root or ap.startswith(root + os.sep):
            sys.exit('[!] refusing to write into %s' % ap)
    return ap

def main():
    if len(sys.argv) < 3:
        print("usage: extract_route_map.py <JSDIR> <OUTDIR>")
        sys.exit(1)
    jsdir, outdir = sys.argv[1], safe_outdir(sys.argv[2])
    os.makedirs(outdir, exist_ok=True)  # lingops:ignore 输出目录已由 safe_outdir() 归一化，拒绝系统/自启目录

    best = {}
    best_file = None
    pat = re.compile(r'([A-Z_][A-Z0-9_]*):\{name:"([^"]*)",link:"([^"]+)"')

    for fp in glob.glob(os.path.join(jsdir, '*.js')):
        try:
            txt = open(fp, encoding='utf-8', errors='ignore').read()
        except Exception:
            continue
        hits = pat.findall(txt)
        if len(hits) > len(best):
            best = {k: {'name': n, 'link': l} for k, n, l in hits}
            best_file = fp

    if not best:
        print('[!] no routeMap pattern found — widen regex or grep manually')
        sys.exit(1)

    out = os.path.join(outdir, 'route_map.json')
    json.dump(best, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print(f'[+] {len(best)} routes from {os.path.basename(best_file)} -> {out}')

if __name__ == '__main__':
    main()
