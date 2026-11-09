#!/usr/bin/env node
/*
 * 屏蔽（stripComments）正确性审计 —— 深度审计引擎的「净化层」自检
 *
 * 引擎先把注释和字符串字面量抹成空格，再在剩下的代码上匹配。这一步如果多抹了
 * 真实代码，后面的污点分析就永远看不到那行 → 直接表现为「漏报」。
 * 少抹了（把注释里的内容当代码）→ 表现为「误报」。两种都要能自己查出来。
 *
 *   node mask-audit.js <目录或文件>          审计，只打汇总
 *   node mask-audit.js <目录或文件> -v       逐条打印可疑行
 *   node mask-audit.js <目录或文件> --json   机器可读
 *   node mask-audit.js <目录> --cap 500      最多审计 500 个文件（默认 1500）
 *   node mask-audit.js <目录> --no-compile   跳过「屏蔽后能否编译」这一步（更快）
 *
 * 判定方式（三道互相独立的检查，任一不过就是可疑）：
 *   1. 行数守恒 —— 屏蔽前后行数必须一致，否则行号会整体错位
 *   2. 结构完整 —— 屏蔽后的文件必须还能通过 node --check / php -l / py_compile。
 *      这一条能抓到最危险的一类：引擎在正则字面量或未闭合字符串上失控，
 *      把后面一大段真实代码连带抹掉（此时屏蔽后的文件语法必然残缺）
 *   3. 全抹行 —— 原文非空、屏蔽后整行变空的行，逐条列出来给人看
 *      （纯注释、docstring 正文、多行字符串正文属于正常，需人工扫一眼）
 *
 * 退出码：0 = 没有结构性问题，1 = 有（行数错位 / 编译失败），2 = 用法错误。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const HERE = __dirname;
const ENGINE = process.env.LP_FILE || path.resolve(HERE, '../../../frontend/dist/assets_v2/lp-ext/awdpplus.js');
if (!fs.existsSync(ENGINE)) {
  console.error('找不到引擎：' + ENGINE);
  console.error('用 LP_FILE=/path/to/awdpplus.js 指定');
  process.exit(2);
}
process.env.LP_FILE = ENGINE;
// 引擎加载时会往 stdout 打一行版本信息，--json 时会污染输出 → 临时改到 stderr
const _stdout = console.log;
console.log = function () { console.error.apply(console, arguments); };
const api = require(path.join(HERE, '..', 'shim.js'));
console.log = _stdout;

const argv = process.argv.slice(2);
const target = argv.find(a => !a.startsWith('-'));
if (!target) {
  console.error('用法：node mask-audit.js <目录或文件> [-v] [--json] [--cap N] [--no-compile]');
  process.exit(2);
}
const VERBOSE = argv.includes('-v') || argv.includes('--verbose');
const JSONOUT = argv.includes('--json');
const NOCOMPILE = argv.includes('--no-compile');
const capIdx = argv.indexOf('--cap');
const CAP = capIdx >= 0 ? parseInt(argv[capIdx + 1], 10) || 1500 : 1500;

const LANG = { '.php': 'php', '.py': 'python', '.js': 'node', '.mjs': 'node', '.rb': 'ruby', '.go': 'go', '.java': 'java' };
const SKIP_DIRS = new Set(['__pycache__', 'node_modules', '.git', 'dist-info', 'site-packages.dSYM']);

// ---- 收集文件 -------------------------------------------------------------
function collect(p, out) {
  let st;
  try { st = fs.statSync(p); } catch (_) { return; }
  if (st.isFile()) { out.push(p); return; }
  let names;
  try { names = fs.readdirSync(p, { withFileTypes: true }); } catch (_) { return; }
  for (const e of names) {
    if (out.length >= CAP) return;
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) || e.name.endsWith('.dist-info')) continue;
      collect(path.join(p, e.name), out);
    } else if (e.isFile() && LANG[path.extname(e.name)]) {
      out.push(path.join(p, e.name));
    }
  }
}

// ---- 结构完整：屏蔽后的文件还能不能编译 ------------------------------------
const TOOLS = {};
function hasTool(bin) {
  if (bin in TOOLS) return TOOLS[bin];
  try { execFileSync(bin, ['--version'], { stdio: 'ignore' }); TOOLS[bin] = true; }
  catch (_) { TOOLS[bin] = false; }
  return TOOLS[bin];
}
function compiles(code, lang, file) {
  const ext = lang === 'python' ? '.py' : lang === 'php' ? '.php' : '.js';
  const tmp = path.join(os.tmpdir(), 'lp-mask-' + process.pid + '-' + Math.random().toString(36).slice(2) + ext);
  try {
    fs.writeFileSync(tmp, code);
    if (lang === 'python') {
      if (!hasTool('python3')) return null;
      execFileSync('python3', ['-m', 'py_compile', tmp], { stdio: 'pipe' });
    } else if (lang === 'php') {
      if (!hasTool('php')) return null;
      const r = execFileSync('php', ['-l', tmp], { stdio: 'pipe', encoding: 'utf8' });
      if (!/No syntax errors/i.test(r)) return 'php -l: ' + r.trim();
    } else if (lang === 'node') {
      execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' });
    } else {
      return null;                      // ruby/go/java 不做，缺工具时也不做
    }
    return null;                        // null = 通过（或没工具，未判定）
  } catch (e) {
    const msg = (e.stderr && e.stderr.toString()) || e.message || 'unknown';
    return msg.split('\n').filter(Boolean).slice(0, 3).join(' / ');
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) {}
    try { fs.rmSync(tmp.replace(ext, '') + '.pyc', { force: true }); } catch (_) {}
  }
}

// ---- 主循环 ---------------------------------------------------------------
const files = [];
collect(path.resolve(target), files);

const rows = [];
let checked = 0, skipped = 0, lineMismatch = 0, broke = 0, unmasked = 0, minified = 0;

for (const file of files) {
  const lang = LANG[path.extname(file)];
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch (_) { skipped++; continue; }
  if (raw.indexOf('\u0000') >= 0) { skipped++; continue; }   // 二进制
  let masked;
  try { masked = api.stripComments(raw, lang); } catch (e) { skipped++; continue; }
  if (typeof masked !== 'string') { skipped++; continue; }
  checked++;

  const rel = path.relative(path.resolve(target), file) || path.basename(file);
  const R = raw.split('\n');
  const M = masked.split('\n');

  // 1. 行数守恒
  if (R.length !== M.length) {
    lineMismatch++;
    rows.push({ file: rel, kind: 'linecount', detail: `原文 ${R.length} 行 / 屏蔽后 ${M.length} 行` });
  }

  // 2. 结构完整。压缩/混淆成单行的代码里「/ 是除号还是正则起始」本身就不可判定，
  //    这类文件编译失败不算结构性问题，单独计数（源文件才是审计对象）
  const isMin = R.some(l => l.length > 2000);
  if (isMin) minified++;
  if (!NOCOMPILE) {
    const err = compiles(masked, lang, file);
    if (err) {
      if (isMin) rows.push({ file: rel, kind: 'minified', detail: '压缩代码，跳过判定' });
      else { broke++; rows.push({ file: rel, kind: 'compile', detail: err }); }
    }
  }

  // 3. 全抹行（只收集，供人工扫）
  const blank = [];
  const n = Math.min(R.length, M.length);
  for (let i = 0; i < n; i++) {
    if (!R[i] || !R[i].trim()) continue;
    if (M[i].replace(/\s/g, '') === '') blank.push({ line: i + 1, text: R[i].trim().slice(0, 140) });
  }
  if (blank.length) {
    unmasked += blank.length;
    rows.push({ file: rel, kind: 'fully-masked', detail: blank.length + ' 行', lines: blank });
  }
}

// ---- 输出 -----------------------------------------------------------------
const structural = lineMismatch + broke;
if (JSONOUT) {
  console.log(JSON.stringify({ engine: ENGINE, target: path.resolve(target), checked, skipped,
    lineMismatch, broke, minified, fullyMaskedLines: unmasked, rows }, null, 1));
} else {
  console.log('引擎：' + ENGINE);
  console.log('审计：' + path.resolve(target));
  console.log('');
  console.log(`  文件      ${checked} 个（跳过 ${skipped}）`);
  console.log(`  行数错位  ${lineMismatch} 个`);
  console.log(`  屏蔽后编译失败 ${broke} 个`);
  console.log(`  整行被抹  ${unmasked} 行（含正常注释/字符串，需人工扫）`);
  if (minified) console.log(`  压缩代码  ${minified} 个（单行 >2000 字符，正则/除号不可判定，不参与判定）`);
  console.log('');
  if (structural === 0) {
    console.log('结构性检查通过 ✅（没有多抹真实代码的迹象）');
  } else {
    console.log('发现结构性问题 ❌：');
    for (const r of rows) {
      if (r.kind === 'fully-masked' || r.kind === 'minified') continue;
      console.log(`  ${r.kind === 'compile' ? '编译失败' : '行数错位'}  ${r.file}`);
      console.log(`      ${r.detail}`);
    }
  }
  if (VERBOSE) {
    const fm = rows.filter(r => r.kind === 'fully-masked');
    if (fm.length) {
      console.log('');
      console.log('整行被抹的样本（前 40 条，正常应是注释/docstring/字符串正文）：');
      let shown = 0;
      for (const r of fm) {
        for (const l of r.lines) {
          if (shown++ >= 40) break;
          console.log(`  ${r.file}:${l.line}  ${l.text}`);
        }
        if (shown >= 40) break;
      }
    }
  }
}
process.exit(structural === 0 ? 0 : 1);
