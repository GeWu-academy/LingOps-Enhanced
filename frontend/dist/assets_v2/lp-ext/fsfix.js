/* LingOps 扩展：WebShell 文件管理器兼容补丁（由 boot.js 加载）
 *
 * 官方前端的文件管理器把 "/" 当作初始路径与「根目录」：
 *   useEffect(() => w("/"), [shell.id])   // 打开即请求 path=/
 *   D = V => V.isDir ? w(V.path) : A(V)   // 只有 isDir 才进目录
 *
 * 在 Windows 目标上，PHP 侧把 "/" 拼成 "//名字"（PHP 视为 UNC 网络路径），
 * is_dir() 全部失败，于是：
 *   - 所有条目 isDir=false → 图标全是文件、双击只会「读取文件」而不是进目录；
 *   - 列表内容是盘符根（$RECYCLE.BIN、Program Files…），不是上传 shell 的目录；
 *   - 新建/上传时路径拼成 "/名字"，落到盘符根；
 *   - 列表里没有 ".."，无法向上浏览。
 *
 * 本补丁做三件事（只在浏览器端，不改官方代码）：
 *   1. 把 ws/files 请求里的 "/"（含 ""、"/."、"//"）改写成虚拟根，默认 "."，
 *      也就是 shell 所在目录（你上传 shell.php 的地方）；可用
 *      localStorage.lp_fs_root 改成 "C:" 等绝对路径；
 *   2. 给每个目录列表注入一行 ".."（上级目录），双击/单击即可向上；
 *   3. 单击文件夹直接进入（官方只支持双击），并给出一次使用提示。
 */
(function () {
  'use strict';
  if (window.__lpFsFix) return;
  window.__lpFsFix = true;

  var ROOT_KEY = 'lp_fs_root';
  var FILES_RE = /\/api\/v1\/shells\/(\d+)\/ws\/files(\?|$)/;

  function virtualRoot() {
    try {
      var v = localStorage.getItem(ROOT_KEY);
      return v && v.trim() ? v.trim() : '.';
    } catch (e) { return '.'; }
  }

  var last = null; // { id, path, at }：最近一次 ws/files 请求（用于推断父目录）

  function parseUrl(url) {
    var m = FILES_RE.exec(url);
    if (!m) return null;
    var qs = url.indexOf('?') >= 0 ? url.slice(url.indexOf('?') + 1) : '';
    var path = null;
    qs.split('&').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i < 0 || kv.slice(0, i) !== 'path') return;
      try { path = decodeURIComponent(kv.slice(i + 1)); } catch (e) { path = kv.slice(i + 1); }
    });
    return { id: m[1], path: path };
  }

  function isVirtualRootPath(p) {
    return p === null || p === '' || p === '/' || p === '/.' || p === '//' ||
           p === '\\' || p === '.\\';
  }

  function rewriteUrl(url) {
    var info = parseUrl(url);
    if (!info) return url;
    if (!isVirtualRootPath(info.path)) {
      last = { id: info.id, path: info.path, at: Date.now() };
      return url;
    }
    var target = virtualRoot();
    var out = /([?&])path=[^&]*/.test(url)
      ? url.replace(/([?&])path=[^&]*/, '$1path=' + encodeURIComponent(target))
      : url + (url.indexOf('?') < 0 ? '?' : '&') + 'path=' + encodeURIComponent(target);
    last = { id: info.id, path: target, at: Date.now() };
    hintOnce();
    return out;
  }

  // 上级目录：'.'→'..'、'..'→'../..'、'C:/a/b'→'C:/a'、盘符根返回 null
  function parentOf(p) {
    if (!p) return null;
    var q = String(p).replace(/[\\\/]+$/, '');
    if (/^[A-Za-z]:$/.test(q)) return null;
    if (/^\.\.(\/\.\.)*$/.test(q)) return q + '/..';
    if (q === '.') return '..';
    var i = Math.max(q.lastIndexOf('/'), q.lastIndexOf('\\'));
    if (i < 0) return '..';
    var head = q.slice(0, i);
    if (/^[A-Za-z]:$/.test(head)) return head;
    return head || '.';
  }

  function augment(data) {
    if (!Array.isArray(data) || !data.length) return data;
    var info = last;
    if (!info || Date.now() - info.at > 5000) return data;
    var f = data[0];
    if (!f || typeof f !== 'object' || !('isDir' in f) || !('path' in f) || !('name' in f)) return data;
    var par = parentOf(info.path);
    if (!par) return data;
    for (var i = 0; i < data.length; i++) {
      if (data[i] && data[i].name === '..') return data;
    }
    return [{ name: '..', path: par, isDir: true, size: 0, perms: '0777', modTime: '' }].concat(data);
  }

  // 1) 改写请求路径（axios 走 XHR；fetch 兜底）
  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var args = Array.prototype.slice.call(arguments);
    try {
      if (typeof url === 'string' && url.indexOf('/ws/files') >= 0) args[1] = rewriteUrl(url);
    } catch (e) {}
    return origOpen.apply(this, args);
  };

  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function (input) {
      var args = Array.prototype.slice.call(arguments);
      try {
        if (typeof input === 'string' && input.indexOf('/ws/files') >= 0) args[0] = rewriteUrl(input);
      } catch (e) {}
      return origFetch.apply(this, args);
    };
  }

  // 2) 注入 ".." 行（axios 的 transformResponse 用全局 JSON.parse 解析）
  var origParse = JSON.parse;
  JSON.parse = function () {
    var v = origParse.apply(this, arguments);
    try {
      if (v && typeof v === 'object' && v.code === 0 && Array.isArray(v.data)) {
        var d = augment(v.data);
        if (d !== v.data) v.data = d;
      }
    } catch (e) {}
    return v;
  };

  // 3) 单击文件夹直接进入（官方仅支持双击），并避免真双击触发两次
  var lastNav = { el: null, t: 0 };

  function rowOf(e) {
    return e.target && e.target.closest ? e.target.closest('tr.ant-table-row') : null;
  }

  document.addEventListener('click', function (e) {
    var tr = rowOf(e);
    if (!tr || e.detail > 1) return;
    if (!tr.querySelector('td svg[data-icon="folder"]')) return;
    if (lastNav.el === tr && Date.now() - lastNav.t < 800) return;
    tr.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true, view: window }));
    lastNav = { el: tr, t: Date.now() };
  }, true);

  document.addEventListener('dblclick', function (e) {
    var tr = rowOf(e);
    if (!tr) return;
    if (lastNav.el === tr && Date.now() - lastNav.t < 800) {
      e.stopPropagation();
      e.preventDefault();
    }
  }, true);

  // 4) 首次生效提示
  var hintShown = false;
  function hintOnce() {
    if (hintShown) return;
    hintShown = true;
    try {
      if (sessionStorage.getItem('lp_fs_hint')) return;
      sessionStorage.setItem('lp_fs_hint', '1');
    } catch (e) {}
    var root = virtualRoot();
    setTimeout(function () {
      var box = document.createElement('div');
      box.textContent = '文件管理器已定位到 shell 所在目录（' + root + '）；单击文件夹即可进入，双击文件可预览/编辑';
      box.style.cssText = [
        'position:fixed', 'left:50%', 'bottom:36px', 'transform:translateX(-50%)',
        'z-index:2147483600', 'max-width:82vw',
        'background:#153a2b', 'color:#b7f7d0', 'border:1px solid #2f6b4f',
        'padding:9px 16px', 'border-radius:8px', 'font-size:13px', 'line-height:1.6',
        'box-shadow:0 8px 24px rgba(0,0,0,.45)',
        'font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif'
      ].join(';');
      document.body.appendChild(box);
      setTimeout(function () { box.style.transition = 'opacity .4s'; box.style.opacity = '0'; }, 6000);
      setTimeout(function () { if (box.parentNode) box.parentNode.removeChild(box); }, 6600);
    }, 300);
  }

  // 供调试/自动化使用
  window.__lpFsFixInfo = function () { return { root: virtualRoot(), last: last }; };
})();
