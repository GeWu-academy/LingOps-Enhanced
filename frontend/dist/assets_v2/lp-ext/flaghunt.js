/* LingOps 扩展：Flag 查找
 * 解决官方「Flag 读取」只能手工填一个路径、找不到 Flag 的问题：
 *   1. 自动探测目标系统（Windows / Linux）与站点根目录
 *   2. 三种模式搜索 Flag 文件：常用路径（秒出）/ 快速（站点目录+常见目录）/ 深度（全盘）
 *   3. 逐个读取内容，正则提取 flag{...}
 *   4. 一键把命中的路径提交为官方「Flag 监控任务」
 * 纯原生 JS，由 boot.js 动态加载，不修改官方二进制。
 */
(function () {
  'use strict';
  if (window.__lpFlagHunt) return;
  window.__lpFlagHunt = true;

  var API = '/api/v1';
  var MAX_READ = 120;          // 最多读取多少个候选文件
  var EXEC_TIMEOUT = 60000;    // 单条命令超时
  var DEFAULT_RE = 'flag\\{[^}\\r\\n]{1,200}\\}';

  var S = {
    shells: [],
    shellId: null,
    running: false,
    stop: false,
    rows: [],
    os: '',
    webroot: ''
  };

  var ui = {};

  /* ---------- 基础工具 ---------- */

  function tok() { return localStorage.getItem('lingops_token') || ''; }

  function api(method, path, body) {
    var opt = { method: method, headers: { 'Authorization': 'Bearer ' + tok() } };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    return fetch(API + path, opt).then(function (r) {
      return r.json().catch(function () { return { code: 1, message: 'HTTP ' + r.status }; });
    }).catch(function (e) { return { code: 1, message: String(e && e.message || e) }; });
  }

  function exec(shellId, command) {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, EXEC_TIMEOUT);
    return fetch(API + '/shells/' + shellId + '/ws/exec', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + tok(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: command }),
      signal: ctl.signal
    }).then(function (r) { return r.json(); })
      .catch(function (e) { return { code: 1, message: '超时或网络错误: ' + (e && e.message || e) }; })
      .then(function (j) { clearTimeout(timer); return j; });
  }

  function readFile(shellId, path) {
    return api('GET', '/shells/' + shellId + '/ws/read?path=' + encodeURIComponent(path));
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function toast(msg, color) {
    var t = document.createElement('div');
    t.textContent = msg;
    t.style.cssText = 'position:fixed;left:50%;top:76px;transform:translateX(-50%);z-index:2147483600;' +
      'padding:9px 18px;border-radius:8px;font-size:13px;color:#fff;background:' + (color || '#16a34a') +
      ';box-shadow:0 8px 26px rgba(0,0,0,.35);font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif';
    document.body.appendChild(t);
    setTimeout(function () { t.style.transition = 'opacity .4s'; t.style.opacity = '0'; }, 3200);
    setTimeout(function () { t.remove(); }, 3800);
  }

  /* ---------- 搜索命令 ---------- */

  function keywordList(raw) {
    var arr = String(raw || '').split(/[,，\s]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    return arr.length ? arr : ['flag'];
  }

  function buildCommands(os, mode, kw, webroot, drive) {
    var names = keywordList(kw);
    var cmds = [];

    if (os === 'win') {
      var root = webroot && webroot !== 'C:\\' ? webroot : drive + '\\';
      if (mode === 'quick') {
        names.forEach(function (n) {
          cmds.push('dir /s /b "' + root + '\\*' + n + '*" 2>nul');
        });
        cmds.push('dir /b "' + drive + '\\*flag*" 2>nul');
        cmds.push('for /d %d in ("' + drive + '\\*") do @dir /b "%d\\*flag*" 2>nul');
        cmds.push('dir /s /b "C:\\Users\\Public\\*flag*" 2>nul');
        cmds.push('dir /s /b "C:\\Windows\\Temp\\*flag*" 2>nul');
        cmds.push('dir /s /b "C:\\inetpub\\*flag*" 2>nul');
      } else if (mode === 'deep') {
        cmds.push('powershell -NoProfile -Command "Get-PSDrive -PSProvider FileSystem | ' +
          'ForEach-Object { Get-ChildItem -LiteralPath $_.Root -Filter *flag* -Recurse -Depth 5 ' +
          '-File -ErrorAction SilentlyContinue } | Select-Object -First 200 -ExpandProperty FullName"');
        cmds.push('powershell -NoProfile -Command "Get-ChildItem -LiteralPath \'' + drive + '\\\' -Filter *flag* ' +
          '-Recurse -Depth 6 -File -ErrorAction SilentlyContinue | Select-Object -First 200 -ExpandProperty FullName"');
      }
      if (mode !== 'common' && ui.contentSearch && ui.contentSearch.checked) {
        cmds.push('findstr /s /m /i /c:"flag{" "' + root + '\\*.php" "' + root + '\\*.txt" 2>nul');
      }
    } else {
      var wroot = webroot || '/var/www/html';
      if (mode === 'quick') {
        names.forEach(function (n) {
          cmds.push('find "' + wroot + '" -iname "*' + n + '*" 2>/dev/null | head -60');
        });
        cmds.push('ls -d /flag* /root/flag* /tmp/flag* /home/*/flag* /var/www/flag* ' +
          '/var/www/html/flag* /opt/flag* /srv/flag* 2>/dev/null');
        cmds.push('for d in / /root /tmp /var/www /home /opt /srv /usr/local /var/log; do ' +
          'find "$d" -maxdepth 3 -iname "*flag*" 2>/dev/null; done | sort -u | head -80');
      } else if (mode === 'deep') {
        cmds.push('find / -xdev \\( -path /proc -o -path /sys -o -path /dev -o -path /run \\) -prune -o ' +
          '-iname "*flag*" -print 2>/dev/null | head -150');
        cmds.push('find / -xdev \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o ' +
          '-iname "*ctf*" -print 2>/dev/null | head -60');
      }
      if (mode !== 'common' && ui.contentSearch && ui.contentSearch.checked) {
        cmds.push('grep -rIl "flag{" "' + wroot + '" 2>/dev/null | head -40');
      }
    }
    return cmds;
  }

  function commonPaths(os, webroot, drive) {
    if (os === 'win') {
      var root = webroot || (drive + '\\');
      return [
        root + '\\flag', root + '\\flag.txt', root + '\\flag.php', root + '\\flag.html',
        root + '\\..\\flag.txt', root + '\\..\\..\\flag.txt',
        drive + '\\flag', drive + '\\flag.txt', drive + '\\flag.php',
        'C:\\flag', 'C:\\flag.txt', 'C:\\Windows\\Temp\\flag.txt', 'C:\\Users\\Public\\flag.txt',
        'C:\\inetpub\\wwwroot\\flag.txt'
      ];
    }
    return [
      '/flag', '/flag.txt', '/flag.php', '/root/flag', '/root/flag.txt', '/tmp/flag',
      '/var/www/html/flag', '/var/www/html/flag.php', '/var/www/html/flag.txt',
      '/home/ctf/flag', '/opt/flag', '/flag.sh'
    ];
  }

  function parsePaths(os, text) {
    var out = [];
    String(text || '').split(/\r?\n/).forEach(function (line) {
      var s = line.trim();
      if (!s || s.length > 500) return;
      if (os === 'win') {
        if (/^[A-Za-z]:\\/.test(s) || /^\\\\/.test(s)) out.push(s.replace(/\\+$/, ''));
      } else if (s.charAt(0) === '/') {
        out.push(s.replace(/\/+$/, '') || '/');
      }
    });
    return out;
  }

  // PHP 打开失败时若 display_errors 开着会把警告当内容返回，需识别成「不可读」
  function isErrorContent(t) {
    if (!t) return true;
    if (t.length > 600) return false;
    return /(No such file or directory|failed to open stream|Permission denied|is a directory|系统找不到|拒绝访问|__LP_READ_FAIL__)/i.test(t);
  }

  /* ---------- 提取 Flag ---------- */

  function extractFlags(text, loose) {
    var res = [];
    var patterns = [DEFAULT_RE];
    if (loose) patterns.push('[A-Za-z][A-Za-z0-9_]{1,15}\\{[A-Za-z0-9_+\\-/=]{6,}\}');
    patterns.forEach(function (p) {
      var re;
      try { re = new RegExp(p, 'gi'); } catch (e) { return; }
      var m;
      while ((m = re.exec(text)) !== null) {
        if (res.indexOf(m[0]) < 0) res.push(m[0]);
        if (res.length > 12) break;
      }
    });
    return res;
  }

  /* ---------- UI ---------- */

  function css() {
    return '' +
      '#lp-fh{position:fixed;inset:0;z-index:2147483400;background:rgba(0,0,0,.55);display:none;' +
      'align-items:center;justify-content:center;padding:24px;font:13px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}' +
      '#lp-fh-box{width:min(1240px,96vw);height:90vh;background:#101418;border:1px solid #2a323b;border-radius:12px;' +
      'display:flex;flex-direction:column;overflow:hidden;box-shadow:0 12px 48px rgba(0,0,0,.6);color:#e6edf3}' +
      '#lp-fh-bar{height:46px;flex:0 0 46px;display:flex;align-items:center;justify-content:space-between;' +
      'padding:0 14px;background:#171d23;border-bottom:1px solid #2a323b}' +
      '#lp-fh-bar b{font-size:14px;font-weight:600}' +
      '#lp-fh-close{background:transparent;border:1px solid #2a323b;color:#8b98a5;border-radius:6px;' +
      'padding:4px 12px;cursor:pointer;font-size:12px}' +
      '#lp-fh-close:hover{color:#ff4d4f;border-color:#ff4d4f}' +
      '#lp-fh-form{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:12px 14px;border-bottom:1px solid #222a32}' +
      '#lp-fh-form label{color:#8b98a5;font-size:12px}' +
      '#lp-fh select,#lp-fh input[type=text]{background:#0b0f13;border:1px solid #2a323b;color:#e6edf3;' +
      'border-radius:6px;padding:5px 8px;font-size:12px;outline:none}' +
      '#lp-fh select:focus,#lp-fh input[type=text]:focus{border-color:#1890ff}' +
      '.lp-fh-btn{background:#1890ff;border:0;color:#fff;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px}' +
      '.lp-fh-btn:hover{background:#40a9ff}' +
      '.lp-fh-btn.ghost{background:transparent;border:1px solid #2a323b;color:#c9d4de}' +
      '.lp-fh-btn.ghost:hover{border-color:#1890ff;color:#1890ff}' +
      '.lp-fh-btn:disabled{opacity:.45;cursor:not-allowed}' +
      '#lp-fh-status{padding:8px 14px;color:#8b98a5;font-size:12px;display:flex;gap:14px;align-items:center;' +
      'border-bottom:1px solid #222a32;flex:0 0 auto}' +
      '#lp-fh-prog{flex:1 1 auto;height:4px;background:#1b232b;border-radius:2px;overflow:hidden}' +
      '#lp-fh-prog i{display:block;height:100%;width:0;background:#1890ff;transition:width .2s}' +
      '#lp-fh-body{flex:1 1 auto;overflow:auto;padding:0 4px 8px}' +
      '#lp-fh table{width:100%;border-collapse:collapse;font-size:12px}' +
      '#lp-fh th{position:sticky;top:0;background:#161c22;color:#8b98a5;font-weight:500;text-align:left;' +
      'padding:8px 10px;border-bottom:1px solid #2a323b;white-space:nowrap;z-index:2}' +
      '#lp-fh td{padding:7px 10px;border-bottom:1px solid #1c242c;vertical-align:top;word-break:break-all}' +
      '#lp-fh tr:hover td{background:#151b21}' +
      '.lp-fh-path{color:#c9d4de;font-family:ui-monospace,Menlo,Consolas,monospace}' +
      '.lp-fh-flag{color:#52c41a;font-family:ui-monospace,Menlo,Consolas,monospace;cursor:pointer}' +
      '.lp-fh-mut{color:#6b7684}' +
      '.lp-fh-tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;line-height:17px}' +
      '.lp-fh-tag.dir{background:#2b2418;color:#f59e0b}' +
      '.lp-fh-tag.file{background:#14251a;color:#52c41a}' +
      '.lp-fh-tag.err{background:#2b1a1a;color:#ff7875}' +
      '#lp-fh-foot{flex:0 0 auto;padding:10px 14px;border-top:1px solid #2a323b;display:flex;gap:12px;' +
      'align-items:center;color:#8b98a5;font-size:12px;background:#141a20}' +
      '#lp-fh-preview{position:fixed;inset:0;z-index:2147483500;background:rgba(0,0,0,.6);display:none;' +
      'align-items:center;justify-content:center;padding:40px}' +
      '#lp-fh-preview pre{width:min(900px,92vw);max-height:80vh;overflow:auto;background:#0b0f13;' +
      'border:1px solid #2a323b;border-radius:10px;padding:16px;color:#d6dee6;font-size:12px;white-space:pre-wrap;word-break:break-all}';
  }

  function ensureUI() {
    if (document.getElementById('lp-fh')) return;
    var st = document.createElement('style');
    st.textContent = css();
    document.head.appendChild(st);

    var wrap = document.createElement('div');
    wrap.id = 'lp-fh';
    wrap.innerHTML = '' +
      '<div id="lp-fh-box">' +
      '  <div id="lp-fh-bar"><b>🔍 Flag 查找</b><button id="lp-fh-close">关闭 ✕</button></div>' +
      '  <div id="lp-fh-form">' +
      '    <label>WebShell</label><select id="lp-fh-shell"></select>' +
      '    <label>模式</label><select id="lp-fh-mode">' +
      '      <option value="common">常用路径（秒出）</option>' +
      '      <option value="quick" selected>快速（站点目录 + 常见目录）</option>' +
      '      <option value="deep">深度（全盘，较慢）</option>' +
      '    </select>' +
      '    <label>关键词</label><input id="lp-fh-kw" type="text" value="flag" style="width:130px" ' +
      'title="逗号分隔，如 flag,ctf,key">' +
      '    <label><input id="lp-fh-content" type="checkbox" checked> 同时搜文件内容（站点目录）</label>' +
      '    <label><input id="lp-fh-loose" type="checkbox"> 宽松匹配（任意 xxx{...}）</label>' +
      '    <label><input id="lp-fh-onlyhits" type="checkbox"> 只看含 Flag</label>' +
      '    <button class="lp-fh-btn" id="lp-fh-run">开始查找</button>' +
      '    <button class="lp-fh-btn ghost" id="lp-fh-stop" disabled>停止</button>' +
      '  </div>' +
      '  <div id="lp-fh-form" style="border-top:0;padding-top:0">' +
      '    <label>直接读取</label>' +
      '    <input id="lp-fh-readpath" type="text" placeholder="粘贴文件路径，如 /flag 或 C:\\flag.txt" style="flex:1 1 320px;min-width:220px">' +
      '    <button class="lp-fh-btn ghost" id="lp-fh-readbtn">读取并提取</button>' +
      '  </div>' +
      '  <div id="lp-fh-status"><span id="lp-fh-msg">选择 WebShell 后点「开始查找」</span>' +
      '    <span id="lp-fh-prog"><i></i></span></div>' +
      '  <div id="lp-fh-body"><table><thead><tr>' +
      '    <th style="width:46%">路径</th><th style="width:70px">类型</th>' +
      '    <th style="width:24%">Flag / 内容摘要</th><th style="width:150px">操作</th>' +
      '  </tr></thead><tbody id="lp-fh-rows"></tbody></table></div>' +
      '  <div id="lp-fh-foot"><span id="lp-fh-sum">—</span>' +
      '    <button class="lp-fh-btn ghost" id="lp-fh-all">把命中的全部加入监控</button>' +
      '    <button class="lp-fh-btn ghost" id="lp-fh-copy">复制所有路径</button>' +
      '  </div>' +
      '</div>' +
      '<div id="lp-fh-preview"><pre></pre></div>';
    document.body.appendChild(wrap);

    ui.wrap = wrap;
    ui.shell = wrap.querySelector('#lp-fh-shell');
    ui.mode = wrap.querySelector('#lp-fh-mode');
    ui.kw = wrap.querySelector('#lp-fh-kw');
    ui.contentSearch = wrap.querySelector('#lp-fh-content');
    ui.loose = wrap.querySelector('#lp-fh-loose');
    ui.onlyHits = wrap.querySelector('#lp-fh-onlyhits');
    ui.readPath = wrap.querySelector('#lp-fh-readpath');
    ui.readBtn = wrap.querySelector('#lp-fh-readbtn');
    ui.run = wrap.querySelector('#lp-fh-run');
    ui.stop = wrap.querySelector('#lp-fh-stop');
    ui.msg = wrap.querySelector('#lp-fh-msg');
    ui.prog = wrap.querySelector('#lp-fh-prog i');
    ui.rows = wrap.querySelector('#lp-fh-rows');
    ui.sum = wrap.querySelector('#lp-fh-sum');
    ui.preview = wrap.querySelector('#lp-fh-preview');

    wrap.querySelector('#lp-fh-close').onclick = close;
    wrap.addEventListener('click', function (e) { if (e.target === wrap) close(); });
    ui.preview.addEventListener('click', function () { ui.preview.style.display = 'none'; });
    ui.run.onclick = start;
    ui.onlyHits.onchange = function () {
      [].slice.call(ui.rows.children).forEach(function (tr) {
        var hit = !!tr.querySelector('.lp-fh-flag');
        tr.style.display = (ui.onlyHits.checked && !hit) ? 'none' : '';
      });
    };
    ui.readBtn.onclick = directRead;
    ui.readPath.onkeydown = function (e) { if (e.key === 'Enter') directRead(); };
    ui.stop.onclick = function () { S.stop = true; ui.msg.textContent = '正在停止…'; };
    wrap.querySelector('#lp-fh-all').onclick = addAllTasks;
    wrap.querySelector('#lp-fh-copy').onclick = function () {
      var txt = S.rows.map(function (r) { return r.path; }).join('\n');
      navigator.clipboard && navigator.clipboard.writeText(txt);
      toast('已复制 ' + S.rows.length + ' 条路径');
    };
    ui.shell.onchange = function () { S.shellId = Number(ui.shell.value); };
  }

  function open() {
    ensureUI();
    ui.wrap.style.display = 'flex';
    loadShells();
  }
  function close() { if (ui.wrap) ui.wrap.style.display = 'none'; }

  function loadShells() {
    api('GET', '/shells?page=1&page_size=100').then(function (j) {
      var items = (j.data && j.data.items) || [];
      S.shells = items;
      ui.shell.innerHTML = items.length ? '' : '<option value="">（无 WebShell）</option>';
      items.forEach(function (s) {
        var o = document.createElement('option');
        o.value = s.id;
        o.textContent = '#' + s.id + ' ' + s.name + (s.status === 'online' ? '（在线）' : '（' + s.status + '）');
        ui.shell.appendChild(o);
      });
      var online = items.filter(function (s) { return s.status === 'online'; })[0];
      S.shellId = online ? online.id : (items[0] && items[0].id);
      if (S.shellId) ui.shell.value = S.shellId;
    });
  }

  function setStatus(msg) { ui.msg.textContent = msg; }
  function setProgress(p) { ui.prog.style.width = Math.max(0, Math.min(100, p)) + '%'; }

  function clearRows() {
    S.rows = [];
    ui.rows.innerHTML = '';
    ui.sum.textContent = '—';
  }

  /* ---------- 主流程 ---------- */

  function start() {
    if (S.running) return;
    var id = Number(ui.shell.value || S.shellId);
    if (!id) { toast('请先添加一个 WebShell', '#ff4d4f'); return; }
    S.shellId = id;
    S.running = true;
    S.stop = false;
    ui.run.disabled = true;
    ui.stop.disabled = false;
    clearRows();
    setProgress(2);
    run(id).catch(function (e) {
      setStatus('出错: ' + (e && e.message || e));
    }).then(function () {
      S.running = false;
      ui.run.disabled = false;
      ui.stop.disabled = true;
      setProgress(100);
    });
  }

  async function run(shellId) {
    var mode = ui.mode.value;
    setStatus('探测目标系统…');
    setProgress(5);

    var probe = await exec(shellId, 'cd');
    var pout = ((probe.data && probe.data.output) || '').trim();
    var os = /^[A-Za-z]:/.test(pout) ? 'win' : 'linux';
    var webroot = '';
    if (os === 'win') {
      webroot = pout.replace(/\\+$/, '');
    } else {
      var p = await exec(shellId, 'pwd');
      webroot = (((p.data && p.data.output) || '').trim() || '/var/www/html').split(/\r?\n/)[0];
    }
    var drive = os === 'win' ? (webroot.slice(0, 2) || 'C:') : '';
    S.os = os;
    S.webroot = webroot;
    setStatus('目标: ' + (os === 'win' ? 'Windows' : 'Linux') + ' · 站点目录 ' + webroot + ' · 模式 ' + mode);
    setProgress(10);

    var candidates = [];
    var seen = {};

    function push(p) {
      var k = os === 'win' ? p.toLowerCase() : p;
      if (!p || seen[k]) return;
      seen[k] = 1;
      candidates.push(p);
    }

    // 1) 常用路径先直接试读（最快出结果）
    var commons = commonPaths(os, webroot, drive);
    for (var i = 0; i < commons.length; i++) {
      if (S.stop) break;
      var c = commons[i];
      var r = await readFile(shellId, c);
      var rc = (r && r.code === 0 && r.data && typeof r.data.content === 'string') ? r.data.content : '';
      if (rc && !isErrorContent(rc)) {
        push(c);
        addRow({ path: c, kind: 'file', content: rc, flags: extractFlags(rc, ui.loose.checked) });
      }
      setProgress(10 + (i + 1) / commons.length * 15);
    }

    if (mode === 'common' || S.stop) { finish(); return; }

    // 2) 执行搜索命令
    var cmds = buildCommands(os, mode, ui.kw.value, webroot, drive);
    for (var j = 0; j < cmds.length; j++) {
      if (S.stop) break;
      setStatus('搜索中 (' + (j + 1) + '/' + cmds.length + ')… 已发现 ' + candidates.length + ' 个');
      var res = await exec(shellId, cmds[j]);
      var out = (res && res.data && res.data.output) || '';
      parsePaths(os, out).forEach(push);
      setProgress(25 + (j + 1) / cmds.length * 35);
    }

    // 3) 逐个读取内容
    var total = Math.min(candidates.length, MAX_READ);
    var hits = 0;
    for (var k = 0; k < total; k++) {
      if (S.stop) break;
      var path = candidates[k];
      setStatus('读取 ' + (k + 1) + '/' + total + '… 命中 ' + hits);
      var rr = await readFile(shellId, path);
      var raw = (rr && rr.code === 0 && rr.data && typeof rr.data.content === 'string') ? rr.data.content : '';
      var ok = !!raw && !isErrorContent(raw);
      var content = ok ? raw : '';
      var flags = content ? extractFlags(content, ui.loose.checked) : [];
      if (flags.length) hits++;
      addRow({
        path: path,
        kind: ok ? 'file' : 'dir',
        content: content,
        flags: flags,
        err: ok ? '' : ((rr && rr.message) || '无法读取（可能是目录）')
      });
      setProgress(60 + (k + 1) / total * 38);
    }
    if (candidates.length > MAX_READ) {
      toast('候选过多，只读取前 ' + MAX_READ + ' 个（可换「常用路径」模式精确定位）', '#f59e0b');
    }
    finish();
  }

  function finish() {
    sortRows();
    var hit = S.rows.filter(function (r) { return r.flags && r.flags.length; }).length;
    setStatus(S.stop ? '已停止' : '完成：' + S.rows.length + ' 个候选，' + hit + ' 个含 Flag');
    if (hit) toast('找到 ' + hit + ' 个 Flag');
  }

  function renderRow(row) {
    var tr = document.createElement('tr');
    var flagText = row.flags && row.flags.length ? row.flags.join('\n') : '';
    var brief = row.content ? row.content.replace(/\s+/g, ' ').slice(0, 90) : (row.err || '');
    var tag = row.kind === 'file' ? '<span class="lp-fh-tag file">文件</span>'
      : '<span class="lp-fh-tag dir">目录/不可读</span>';

    tr.innerHTML = '<td class="lp-fh-path">' + esc(row.path) + '</td>' +
      '<td>' + tag + '</td>' +
      '<td>' + (flagText
        ? '<span class="lp-fh-flag">' + esc(flagText) + '</span>'
        : '<span class="lp-fh-mut">' + esc(brief || '—') + '</span>') + '</td>' +
      '<td><button class="lp-fh-btn ghost lp-fh-task">加入监控</button> ' +
      (row.content ? '<button class="lp-fh-btn ghost lp-fh-view">查看</button>' : '') + '</td>';

    var btnTask = tr.querySelector('.lp-fh-task');
    if (btnTask) btnTask.onclick = function () { createTask(row.path, btnTask); };
    var btnView = tr.querySelector('.lp-fh-view');
    if (btnView) btnView.onclick = function () {
      ui.preview.querySelector('pre').textContent = row.content;
      ui.preview.style.display = 'flex';
    };
    var flagEl = tr.querySelector('.lp-fh-flag');
    if (flagEl) flagEl.onclick = function () {
      navigator.clipboard && navigator.clipboard.writeText(flagText);
      toast('已复制 ' + flagText);
    };
    if (ui.onlyHits && ui.onlyHits.checked && !flagText) tr.style.display = 'none';
    return tr;
  }

  function addRow(row) {
    for (var i = 0; i < S.rows.length; i++) {
      if (S.rows[i].path === row.path) return;   // 去重
    }
    S.rows.push(row);
    ui.rows.appendChild(renderRow(row));
    updateSum();
  }

  function updateSum() {
    var hit = S.rows.filter(function (r) { return r.flags && r.flags.length; }).length;
    var readable = S.rows.filter(function (r) { return r.kind === 'file'; }).length;
    ui.sum.textContent = '共 ' + S.rows.length + ' 个候选 · 可读 ' + readable + ' · 含 Flag ' + hit;
  }

  // 命中置顶，其次可读文件，最后目录/不可读
  function sortRows() {
    S.rows.sort(function (a, b) {
      var ha = (a.flags && a.flags.length) ? 2 : (a.kind === 'file' ? 1 : 0);
      var hb = (b.flags && b.flags.length) ? 2 : (b.kind === 'file' ? 1 : 0);
      return hb - ha;
    });
    ui.rows.innerHTML = '';
    S.rows.forEach(function (r) { ui.rows.appendChild(renderRow(r)); });
    updateSum();
  }

  function directRead() {
    var path = (ui.readPath.value || '').trim();
    if (!path) return;
    var id = Number(ui.shell.value || S.shellId);
    if (!id) { toast('请先选择 WebShell', '#ff4d4f'); return; }
    ui.readBtn.disabled = true;
    readFile(id, path).then(function (j) {
      ui.readBtn.disabled = false;
      if (!j || j.code !== 0) { toast('读取失败: ' + ((j && j.message) || '未知错误'), '#ff4d4f'); return; }
      var content = (j.data && j.data.content) || '';
      if (!content) { toast('文件不存在或为空', '#f59e0b'); return; }
      if (isErrorContent(content)) { toast('无法读取：' + content.slice(0, 60), '#ff4d4f'); return; }
      var flags = extractFlags(content, ui.loose.checked);
      addRow({ path: path, kind: 'file', content: content, flags: flags });
      ui.preview.querySelector('pre').textContent = content;
      ui.preview.style.display = 'flex';
      if (flags.length) toast('找到 ' + flags.join(' '));
    });
  }

  function createTask(path, btn) {
    if (btn) { btn.disabled = true; btn.textContent = '提交中…'; }
    api('POST', '/flag/tasks', { shell_id: S.shellId, flag_path: path, interval: 30 }).then(function (j) {
      if (j && j.code === 0) {
        if (btn) btn.textContent = '已加入 ✓';
        toast('已创建 Flag 监控任务: ' + path);
        refreshOfficialList();
      } else {
        if (btn) { btn.disabled = false; btn.textContent = '加入监控'; }
        toast('创建失败: ' + ((j && j.message) || '未知错误'), '#ff4d4f');
      }
    });
  }

  function addAllTasks() {
    var paths = S.rows.filter(function (r) { return r.kind === 'file'; }).map(function (r) { return r.path; });
    if (!paths.length) { toast('没有可加入的路径', '#f59e0b'); return; }
    if (!confirm('将把 ' + paths.length + ' 个路径提交为 Flag 监控任务，继续？')) return;
    var n = 0;
    (function next(i) {
      if (i >= paths.length) { toast('已提交 ' + n + ' 个监控任务'); refreshOfficialList(); return; }
      api('POST', '/flag/tasks', { shell_id: S.shellId, flag_path: paths[i], interval: 30 }).then(function (j) {
        if (j && j.code === 0) n++;
        next(i + 1);
      });
    })(0);
  }

  // 提交后顺手刷新官方任务列表（点它页面上的「刷新列表」按钮）
  function refreshOfficialList() {
    var btns = [].slice.call(document.querySelectorAll('button'));
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].textContent.trim() === '刷新列表') { btns[i].click(); return; }
    }
  }

  /* ---------- 入口：侧边栏菜单 + /flag 页面按钮 ---------- */

  function addMenuItem() {
    if (document.querySelector('[data-lp-flag-menu]')) return;
    var first = document.querySelector('.ant-menu-item, .ant-menu-submenu');
    if (!first || !first.parentNode) return;
    var node = first.cloneNode(true);
    node.setAttribute('data-lp-flag-menu', '1');
    node.classList.remove('ant-menu-item-selected', 'ant-menu-submenu-selected', 'ant-menu-submenu-open');
    node.querySelectorAll('.ant-menu-submenu-arrow, .ant-menu-submenu-title').forEach(function (el) {
      if (el.classList.contains('ant-menu-submenu-title')) el.parentNode.removeChild(el);
      else el.remove();
    });
    var anchor = node.querySelector('a');
    if (anchor) anchor.removeAttribute('href');
    var spans = node.querySelectorAll('span');
    var done = false;
    for (var i = spans.length - 1; i >= 0; i--) {
      if (!spans[i].children.length && spans[i].textContent.trim()) {
        spans[i].textContent = 'Flag 查找';
        done = true;
        break;
      }
    }
    if (!done) node.textContent = 'Flag 查找';
    node.title = '在目标主机上搜索并提取 Flag';
    node.addEventListener('click', function (e) {
      e.preventDefault(); e.stopPropagation(); open();
    }, true);
    first.parentNode.insertBefore(node, first.nextSibling);
  }

  function addPageButton() {
    if (!/^\/flag(\/|$|\?)/.test(location.pathname)) return;
    if (document.getElementById('lp-fh-pagebtn')) return;
    var btns = [].slice.call(document.querySelectorAll('button'));
    var target = null;
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].textContent.trim() === '刷新列表') { target = btns[i]; break; }
    }
    if (!target || !target.parentNode) return;
    var b = document.createElement('button');
    b.id = 'lp-fh-pagebtn';
    b.type = 'button';
    b.textContent = '🔍 查找 Flag';
    b.className = target.className || 'ant-btn ant-btn-default';
    b.style.cssText = 'margin-left:8px;border-color:#1890ff;color:#1890ff';
    b.onclick = open;
    target.parentNode.insertBefore(b, target.nextSibling);
  }

  // DOM 一变就重试注入：React 渲染完当帧就能出按钮，不用等 2 秒轮询
  function watchDom(fn) {
    var queued = false;
    function run() {
      queued = false;
      try { fn(); } catch (e) { console.warn('[flaghunt] 注入失败', e); }
    }
    function kick() {
      if (queued) return;
      queued = true;
      if (window.requestAnimationFrame) window.requestAnimationFrame(run);
      else setTimeout(run, 16);
    }
    run();
    if (window.MutationObserver) {
      try {
        new MutationObserver(kick).observe(document.documentElement, { childList: true, subtree: true });
      } catch (e) { /* 老浏览器退回轮询 */ }
    }
    setInterval(run, 5000); // 兜底：没有 DOM 变化时也补齐
  }

  function boot() {
    watchDom(function () { addMenuItem(); addPageButton(); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  window.__lpFlagHuntOpen = open;
  window.__lpFlagHuntState = S;
})();
