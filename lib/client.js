// dsh-log-guardian — 浏览器端告警脚本（以字符串随包分发，宿主经 tapIndex 注入）。
//
// 职责：连接宿主的 /dsh-log-guardian/events WebSocket，收到 alert 后：
//   1. 右上角红色 toast（始终可用，无需权限）；
//   2. 浏览器原生 Notification（首次用户交互时请求一次权限，已授权才弹）。
// 断线自动重连（指数退避）。零依赖、幂等（全局标志防重复注入）。

export const CLIENT_JS = `(function () {
  'use strict';
  if (window.__logGuardianLoaded) return;
  window.__logGuardianLoaded = true;

  function wsUrl() {
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return proto + '//' + location.host + '/dsh-log-guardian/events';
  }

  // ── toast（始终可用） ────────────────────────────────────────────────
  var MAX_TOASTS = 5;
  function showToast(title, body) {
    var host = document.getElementById('log-guardian-toasts');
    if (!host) {
      host = document.createElement('div');
      host.id = 'log-guardian-toasts';
      host.style.cssText = 'position:fixed;top:12px;right:12px;z-index:2147483647;display:flex;flex-direction:column;gap:8px;max-width:380px;pointer-events:none;';
      document.body.appendChild(host);
    }
    while (host.children.length >= MAX_TOASTS) host.removeChild(host.firstChild);

    var el = document.createElement('div');
    el.style.cssText = 'pointer-events:auto;background:#7f1d1d;color:#fff;border:1px solid #ef4444;' +
      'border-radius:8px;padding:10px 12px;font:12px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;' +
      'box-shadow:0 8px 24px rgba(0,0,0,.35);cursor:pointer;word-break:break-word;';
    var titleEl = document.createElement('div');
    titleEl.style.cssText = 'font-weight:700;margin-bottom:4px;';
    titleEl.textContent = title;
    var bodyEl = document.createElement('div');
    bodyEl.style.cssText = 'opacity:.92;max-height:72px;overflow:hidden;';
    bodyEl.textContent = body;
    el.appendChild(titleEl);
    el.appendChild(bodyEl);
    el.addEventListener('click', function () { el.remove(); });
    host.appendChild(el);
    setTimeout(function () { if (el.parentNode) el.remove(); }, 12000);
  }

  // ── 浏览器原生通知（首次交互请求一次权限） ──────────────────────────
  var askedNotification = false;
  function maybeAskNotification() {
    if (askedNotification) return;
    askedNotification = true;
    if (!('Notification' in window)) return;
    try {
      if (Notification.permission === 'default') Notification.requestPermission();
    } catch (e) {}
  }
  document.addEventListener('pointerdown', maybeAskNotification, { once: true, passive: true });

  function desktopNotify(title, body) {
    try {
      if ('Notification' in window && Notification.permission === 'granted') {
        var n = new Notification(title, { body: body, tag: 'dsh-log-guardian' });
        setTimeout(function () { try { n.close(); } catch (e) {} }, 8000);
      }
    } catch (e) {}
  }

  function onAlert(alert) {
    var kw = (alert.keywords || []).join(', ');
    var title = '\\u26A0\\uFE0F DSH 安全告警' + (kw ? '：' + kw : '');
    var body = (alert.file || '') + '\\n' + String(alert.line || '').slice(0, 200);
    showToast(title, body);
    desktopNotify(title.replace(/\\u26A0\\uFE0F /, ''), body.slice(0, 160));
  }

  // ── WebSocket 连接 + 指数退避重连 ─────────────────────────────────────
  var retry = 1000;
  var closed = false;
  function connect() {
    if (closed) return;
    var ws;
    try { ws = new WebSocket(wsUrl()); } catch (e) { schedule(); return; }
    ws.onopen = function () { retry = 1000; };
    ws.onmessage = function (ev) {
      var msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg && msg.type === 'alert' && msg.alert) onAlert(msg.alert);
    };
    ws.onclose = function () { schedule(); };
    ws.onerror = function () { try { ws.close(); } catch (e) {} };
  }
  function schedule() {
    if (closed) return;
    setTimeout(connect, retry);
    retry = Math.min(retry * 2, 30000);
  }
  window.addEventListener('beforeunload', function () { closed = true; });
  connect();
})();
`;
