/* LingOps 扩展：在平台界面内挂载「端口 / 上传点扫描」入口
 * 由 index.html 引入，纯原生 JS，不依赖 React。
 */
(function () {
  'use strict';

  var PANEL_URL = '/assets_v2/lp-ext/panel.html';
  var MENU_ATTR = 'data-lp-ext-menu';
  var overlay = null;

  // 加载 WebShell 文件管理器兼容补丁（Windows 目标下 "/" 根目录不可用）
  if (!window.__lpFsFix && !document.getElementById('lp-ext-fsfix')) {
    var fsfix = document.createElement('script');
    fsfix.id = 'lp-ext-fsfix';
    fsfix.src = '/assets_v2/lp-ext/fsfix.js?v=2';
    fsfix.defer = false;
    document.head.appendChild(fsfix);
  }

  // 加载 Flag 查找扩展（搜索目标主机上的 flag 文件并提交监控任务）
  if (!window.__lpFlagHunt && !document.getElementById('lp-ext-flaghunt')) {
    var fh = document.createElement('script');
    fh.id = 'lp-ext-flaghunt';
    fh.src = '/assets_v2/lp-ext/flaghunt.js?v=4';
    fh.defer = false;
    document.head.appendChild(fh);
  }

  // 加载木马免杀生成器（多档混淆 + 图片马 / 图标伪装）
  if (!window.__lpTrojanPlus && !document.getElementById('lp-ext-trojanplus')) {
    var tp = document.createElement('script');
    tp.id = 'lp-ext-trojanplus';
    tp.src = '/assets_v2/lp-ext/trojanplus.js?v=6';
    tp.defer = false;
    document.head.appendChild(tp);
  }

  // 加载 AWDP 深度审计（跨行污点分析，补官方引擎漏报）
  if (!window.__lpAwdpPlus && !document.getElementById('lp-ext-awdpplus')) {
    var ap = document.createElement('script');
    ap.id = 'lp-ext-awdpplus';
    ap.src = '/assets_v2/lp-ext/awdpplus.js?v=12';
    ap.defer = false;
    document.head.appendChild(ap);
  }

  function openPanel(tab) {
    if (overlay) {
      overlay.style.display = 'flex';
      if (tab) {
        var f = overlay.querySelector('iframe');
        if (f && f.getAttribute('src') !== PANEL_URL + '#' + tab) f.src = PANEL_URL + '#' + tab;
      }
      return;
    }
    overlay = document.createElement('div');
    overlay.id = 'lp-ext-overlay';
    overlay.style.cssText = [
      'position:fixed', 'inset:0', 'z-index:2147483000',
      'background:rgba(0,0,0,.55)', 'display:flex', 'align-items:center',
      'justify-content:center', 'padding:24px'
    ].join(';');

    var box = document.createElement('div');
    box.style.cssText = [
      'width:min(1360px,96vw)', 'height:92vh', 'background:#101418',
      'border:1px solid #2a323b', 'border-radius:12px', 'overflow:hidden',
      'display:flex', 'flex-direction:column', 'box-shadow:0 12px 48px rgba(0,0,0,.6)'
    ].join(';');

    var bar = document.createElement('div');
    bar.style.cssText = [
      'height:44px', 'flex:0 0 44px', 'display:flex', 'align-items:center',
      'justify-content:space-between', 'padding:0 14px',
      'background:#171d23', 'border-bottom:1px solid #2a323b',
      'color:#e6edf3', 'font:13px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif'
    ].join(';');
    bar.innerHTML = '<span style="font-weight:600">端口 / 上传点扫描</span>';

    var close = document.createElement('button');
    close.textContent = '关闭 ✕';
    close.style.cssText = [
      'background:transparent', 'border:1px solid #2a323b', 'color:#8b98a5',
      'border-radius:6px', 'padding:4px 12px', 'cursor:pointer', 'font-size:12px'
    ].join(';');
    close.onmouseenter = function () { close.style.color = '#ff4d4f'; close.style.borderColor = '#ff4d4f'; };
    close.onmouseleave = function () { close.style.color = '#8b98a5'; close.style.borderColor = '#2a323b'; };
    close.onclick = function () { overlay.style.display = 'none'; };
    bar.appendChild(close);

    var frame = document.createElement('iframe');
    frame.src = PANEL_URL + (tab ? '#' + tab : '');
    frame.style.cssText = 'flex:1 1 auto;width:100%;border:0;background:#101418';

    box.appendChild(bar);
    box.appendChild(frame);
    overlay.appendChild(box);
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) overlay.style.display = 'none';
    });
    document.body.appendChild(overlay);
  }

  window.__lpOpenScan = openPanel;

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    if (artexOverlay && artexOverlay.style.display !== 'none') {
      artexOverlay.style.display = 'none';
      return;
    }
    if (overlay && overlay.style.display !== 'none') overlay.style.display = 'none';
  });

  // 右下角悬浮按钮
  function addFab() {
    if (document.getElementById('lp-ext-fab')) return;
    var fab = document.createElement('div');
    fab.id = 'lp-ext-fab';
    fab.title = '端口扫描 / 上传点探测（LingOps 扩展）';
    fab.style.cssText = [
      'position:fixed', 'right:22px', 'bottom:78px', 'z-index:2147482000',
      'display:flex', 'align-items:center', 'gap:7px',
      'padding:9px 16px', 'border-radius:22px', 'cursor:pointer',
      'background:#1890ff', 'color:#fff', 'font-size:13px', 'font-weight:500',
      'box-shadow:0 6px 20px rgba(24,144,255,.45)', 'user-select:none',
      'transition:transform .15s, box-shadow .15s'
    ].join(';');
    fab.innerHTML =
      '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/>' +
      '<path d="M21 21l-4.3-4.3"/></svg><span>端口扫描</span>';
    fab.onmouseenter = function () { fab.style.transform = 'translateY(-2px)'; };
    fab.onmouseleave = function () { fab.style.transform = 'none'; };
    fab.onclick = openPanel;
    document.body.appendChild(fab);
  }

  /* ---- ARTEX（外部自治渗透系统，独立进程 127.0.0.1:8787）---- */
  var ARTEX_URL = 'http://127.0.0.1:8787/';
  var artexOverlay = null;

  function openArtex() {
    if (!artexOverlay) {
      artexOverlay = document.createElement('div');
      artexOverlay.id = 'lp-artex-overlay';
      artexOverlay.style.cssText = [
        'position:fixed', 'inset:0', 'z-index:2147483000',
        'background:#0b0f14', 'display:flex', 'flex-direction:column'
      ].join(';');

      var bar = document.createElement('div');
      bar.style.cssText = [
        'height:44px', 'flex:0 0 44px', 'display:flex', 'align-items:center', 'gap:10px',
        'padding:0 14px', 'background:#171d23', 'border-bottom:1px solid #2a323b',
        'color:#e6edf3', 'font:13px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif'
      ].join(';');
      bar.innerHTML =
        '<span style="font-weight:600">ARTEX · 自治渗透</span>' +
        '<span id="lp-artex-st" style="font-size:12px;color:#8b98a5">检测中…</span>';

      function mkBtn(text, fn) {
        var b = document.createElement('button');
        b.type = 'button';
        b.textContent = text;
        b.style.cssText = [
          'background:transparent', 'border:1px solid #2a323b', 'color:#8b98a5',
          'border-radius:6px', 'padding:4px 12px', 'cursor:pointer', 'font-size:12px'
        ].join(';');
        b.onmouseenter = function () { b.style.color = '#e6edf3'; b.style.borderColor = '#4b5563'; };
        b.onmouseleave = function () { b.style.color = '#8b98a5'; b.style.borderColor = '#2a323b'; };
        b.onclick = fn;
        return b;
      }

      var spacer = document.createElement('span');
      spacer.style.cssText = 'flex:1 1 auto';
      bar.appendChild(spacer);
      bar.appendChild(mkBtn('重新加载', function () {
        var f = artexOverlay.querySelector('iframe');
        if (f) f.src = ARTEX_URL;
        probeArtex();
      }));
      bar.appendChild(mkBtn('新窗口打开', function () {
        window.open(ARTEX_URL, '_blank', 'noopener');
      }));
      var close = mkBtn('关闭 ✕', function () { artexOverlay.style.display = 'none'; });
      close.onmouseenter = function () { close.style.color = '#ff4d4f'; close.style.borderColor = '#ff4d4f'; };
      close.onmouseleave = function () { close.style.color = '#8b98a5'; close.style.borderColor = '#2a323b'; };
      bar.appendChild(close);

      var frame = document.createElement('iframe');
      frame.src = ARTEX_URL;
      frame.style.cssText = 'flex:1 1 auto;width:100%;border:0;background:#0b0f14';

      artexOverlay.appendChild(bar);
      artexOverlay.appendChild(frame);
      document.body.appendChild(artexOverlay);
    }
    artexOverlay.style.display = 'flex';
    probeArtex();
  }

  // ARTEX 是独立进程：no-cors 只能判断「网络可达」，能连上就说明 8787 有服务
  function probeArtex() {
    var st = document.getElementById('lp-artex-st');
    function set(txt, color) {
      if (!st) return;
      st.textContent = txt;
      st.style.color = color;
    }
    if (!window.fetch) { set('', '#8b98a5'); return; }
    set('检测中…', '#8b98a5');
    fetch(ARTEX_URL, { mode: 'no-cors', cache: 'no-store' })
      .then(function () { set('已连接 127.0.0.1:8787', '#7ee787'); })
      .catch(function () {
        set('未启动 → 在 LingOps 目录执行 ./start.sh', '#ff7875');
      });
  }

  // 侧边栏菜单项（克隆「总览」保持样式一致）
  var MENU_ITEMS = [
    { key: 'scan', text: '端口扫描', title: '端口扫描 / 上传点探测', open: function () { openPanel(); } },
    { key: 'artex', text: 'ARTEX', title: 'ARTEX 自治渗透（LLM 多智能体，独立进程 8787）', open: function () { openArtex(); } }
  ];

  function buildMenuItem(first, item) {
    var node = first.cloneNode(true);
    node.classList.remove('ant-menu-item-selected', 'ant-menu-submenu-selected',
                          'ant-menu-submenu-open');
    node.querySelectorAll('.ant-menu-submenu-arrow, .ant-menu-submenu-title').forEach(function (el) {
      if (el.classList.contains('ant-menu-submenu-title')) el.parentNode.removeChild(el);
      else el.remove();
    });
    var anchor = node.querySelector('a');
    if (anchor) anchor.removeAttribute('href');
    var spans = node.querySelectorAll('span');
    var textSet = false;
    for (var i = spans.length - 1; i >= 0; i--) {
      if (!spans[i].children.length && spans[i].textContent.trim()) {
        spans[i].textContent = item.text;
        textSet = true;
        break;
      }
    }
    if (!textSet) node.textContent = item.text;
    node.title = item.title;
    node.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      item.open();
    }, true);
    return node;
  }

  function addMenuItem() {
    var first = document.querySelector('.ant-menu-item, .ant-menu-submenu');
    if (!first || !first.parentNode) return;
    var after = first;
    for (var i = 0; i < MENU_ITEMS.length; i++) {
      var item = MENU_ITEMS[i];
      if (document.querySelector('[' + MENU_ATTR + '="' + item.key + '"]')) continue;
      var node = buildMenuItem(first, item);
      node.setAttribute(MENU_ATTR, item.key);
      after.parentNode.insertBefore(node, after.nextSibling);
      after = node;
    }
  }

  // 官方 SPA 自带一个「团队」菜单（{path:"/team",title:"团队"}），点进去只有
  // 「团队信息、成员管理等功能正在开发中...」。扩展版的团队作战室已移除，
  // 这个空占位项也一起藏掉；直接访问 /team 时回首页。
  // 用 display:none 而不是删节点：菜单是 React 渲染的，删 DOM 会让它在卸载时抛 removeChild 错。
  var TEAM_HIDDEN = 'data-lp-ext-team-hidden';
  function hideTeamMenu() {
    // 官方菜单用 antd 的 items API 渲染（{key,icon,label}），没有 <a href>，只能按文字认。
    var items = document.querySelectorAll('.ant-menu-item');
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (it.getAttribute(MENU_ATTR)) continue;          // 自己注入的，别误伤
      if ((it.textContent || '').replace(/\s+/g, '') !== '团队') continue;
      it.style.display = 'none';
      it.setAttribute(TEAM_HIDDEN, '1');
    }
    if (location.pathname === '/team') {
      try { location.replace('/'); } catch (e) { /* 忽略 */ }
    }
  }

  // 「侦察 → 探测」页面：官方探测只发 ICMP，丢弃 ICMP 的靶机会被误判离线
  var DISC_ATTR = 'data-lp-ext-discover';
  function hookDiscovery() {
    if (!/\/discovery/i.test(location.pathname)) return;
    if (document.querySelector('[' + DISC_ATTR + ']')) return;
    var btns = document.querySelectorAll('button');
    var anchor = null;
    for (var i = 0; i < btns.length; i++) {
      var t = (btns[i].textContent || '').trim();
      if (t === '开始探测' || t === '开始扫描' || t === '探测') { anchor = btns[i]; break; }
    }
    if (!anchor || !anchor.parentNode) return;

    var btn = document.createElement('button');
    btn.setAttribute(DISC_ATTR, '1');
    btn.type = 'button';
    btn.textContent = '深度探活（ICMP+TCP）';
    btn.title = '官方探测只发 ICMP；丢弃 ICMP 的靶机会显示离线。这里用 TCP 端口兜底重新探测';
    btn.className = anchor.className;
    btn.style.marginLeft = '8px';
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      openPanel('discover');
    }, true);
    anchor.parentNode.insertBefore(btn, anchor.nextSibling);
  }

  // DOM 一变就重试注入：React 渲染完当帧就能出按钮，不用等 2 秒轮询
  function watchDom(fn) {
    var queued = false;
    function run() {
      queued = false;
      try { fn(); } catch (e) { console.warn('[lp-ext] 注入失败', e); }
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
    addFab();
    watchDom(function () { hideTeamMenu(); addMenuItem(); hookDiscovery(); });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
