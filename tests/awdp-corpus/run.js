#!/usr/bin/env node
/*
 * AWDP 深度审计引擎 · 回归自测
 *
 *   node run.js              跑全部 4 套语料，只打汇总
 *   node run.js -v           逐文件打印命中/漏报/误报
 *   node run.js --json       机器可读输出
 *
 * 换引擎（比如测自己改过的版本）：
 *   LP_FILE=/path/to/awdpplus.js node run.js
 *
 * 退出码：0 = 全部通过，1 = 有回归。
 */
const fs = require('fs');
const path = require('path');

const HERE = __dirname;
const ENGINE = process.env.LP_FILE || path.resolve(HERE, '../../frontend/dist/assets_v2/lp-ext/awdpplus.js');
if (!fs.existsSync(ENGINE)) {
  console.error('找不到引擎：' + ENGINE);
  console.error('用 LP_FILE=/path/to/awdpplus.js node run.js 指定');
  process.exit(2);
}
process.env.LP_FILE = ENGINE;          // shim 在 require 时读这个变量
// 引擎加载时会往 stdout 打一行版本信息，--json 时会污染输出 → 临时改到 stderr
const _stdout = console.log;
console.log = function () { console.error.apply(console, arguments); };
const api = require(path.join(HERE, 'shim.js'));
console.log = _stdout;

const VERBOSE = process.argv.includes('-v') || process.argv.includes('--verbose');
const JSONOUT = process.argv.includes('--json');

const LANG = { '.php': 'php', '.py': 'python', '.js': 'node', '.java': 'java', '.go': 'go', '.rb': 'ruby', '.cs': 'csharp', '.asp': 'asp' };
const CORPUS = path.join(HERE, 'corpus');

// expect: 'hit' = 每个文件都必须报出问题；'clean' = 一个都不许报；'high' = 必须报出高危以上
const SUITES = [
  { dir: 'vuln', expect: 'hit', label: '真漏洞' },
  { dir: 'safe', expect: 'clean', label: '安全代码' },
  { dir: 'regress', expect: 'hit', label: '回归' },
  { dir: 'modern', expect: 'hit', label: '新型漏洞' },
  { dir: 'adversarial', expect: 'high', label: '对抗语料',
    // 已文档化的盲区：obj[k]=v 与 arr[i]=x 在无类型信息时不可区分，只报低置信
    knownMiss: ['x08_js_proto_direct.js'] }
];

function scanFile(file) {
  const lang = LANG[path.extname(file)];
  if (!lang) return null;
  const r = api.analyzeText(file, fs.readFileSync(file, 'utf8'), lang, {});
  return Array.isArray(r) ? r : (r && r.findings) || [];
}

const results = [];
let failed = 0;

for (const suite of SUITES) {
  const dir = path.join(CORPUS, suite.dir);
  if (!fs.existsSync(dir)) continue;
  const rows = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const findings = scanFile(path.join(dir, name));
    if (!findings) continue;
    const hasHigh = findings.some(f => f.sev === 'high' || f.sev === 'critical');
    let ok;
    if (suite.expect === 'clean') ok = findings.length === 0;
    else if (suite.expect === 'high') ok = hasHigh;
    else ok = findings.length > 0;
    const known = !ok && (suite.knownMiss || []).includes(name);
    if (!ok && !known) failed++;
    rows.push({ file: name, ok: ok || known, known, findings: findings.map(f => f.sev + '/' + f.cat + '/' + f.name + '@' + f.line) });
  }
  const known = rows.filter(r => r.known).length;
  const pass = rows.length - known - rows.filter(r => !r.ok).length;
  results.push({ suite: suite.label, dir: suite.dir, pass, known, total: rows.length, rows });
}

if (!results.length) {
  console.error('没找到语料目录：' + CORPUS);
  console.error('发布包里不带故意埋洞的回归语料（tests/awdp-corpus/corpus/），');
  console.error('要跑自测请用源码仓库，或把语料放回该目录后重跑。');
  process.exit(3);
}

if (JSONOUT) {
  console.log(JSON.stringify({ engine: ENGINE, failed, results }, null, 1));
} else {
  console.log('引擎：' + ENGINE);
  console.log('');
  for (const r of results) {
    const pct = r.total ? (r.pass / r.total * 100).toFixed(1) : '0.0';
    // pass 已扣除已知盲区
    const extra = r.known ? `  （另有 ${r.known} 个已知盲区不计分）` : '';
    console.log(`  ${r.suite}  ${String(r.pass).padStart(3)}/${String(r.total).padEnd(3)} ${pct.padStart(5)}%` +
      (r.pass + r.known === r.total ? '  ✅' : '  ❌') + extra);
    if (VERBOSE) {
      for (const row of r.rows) {
        if (row.ok) {
          const tag = row.known ? '已知盲区' : 'ok  ';
          console.log(`      ${tag} ${row.file}` + (row.findings.length ? '  ' + row.findings.join(' | ') : ''));
        } else {
          console.log(`      FAIL ${row.file}` + (row.findings.length ? '  ' + row.findings.join(' | ') : '  没报出任何问题'));
        }
      }
    }
  }
  console.log('');
  console.log(failed === 0 ? '全部通过 ✅' : `${failed} 个文件不符合预期 ❌（加 -v 看是哪些）`);
}

process.exit(failed === 0 ? 0 : 1);
