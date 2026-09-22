// dom-sink-hooker — sink-hook.js (v2, erweitert)
// Im Seitenkontext ausfuehren, BEVOR Sources getriggert werden.
// Loggt Sink-Aufrufe nach window.__xssLog. Reines Analyse-Werkzeug.

(() => {
  if (window.__xssHooksInstalled) return 'already installed';
  window.__xssHooksInstalled = true;

  const MARKERS = (window.__XSS_MARKERS || ['DX_XSS', 'xss7q3z']);
  const MAXLEN = 300;
  const MAXLOG = 5000;
  window.__xssLog = [];

  const snippet = (v) => {
    let s;
    try { s = typeof v === 'string' ? v : String(v); } catch (e) { s = '<unserializable>'; }
    return s.length > MAXLEN ? s.slice(0, MAXLEN) + '...[truncated]' : s;
  };

  const tainted = (s) => MARKERS.some((m) => s.includes(m));

  const record = (sink, value, extra) => {
    try {
      if (window.__xssLog.length >= MAXLOG) return;
      const sn = snippet(value);
      const entry = {
        t: new Date().toISOString(),
        sink,
        tainted: tainted(sn),
        value: sn,
        extra: extra || null,
        stack: (new Error()).stack || null
      };
      window.__xssLog.push(entry);
      if (entry.tainted) console.warn('[sink-hook] TAINTED ->', sink, sn);
    } catch (e) {}
  };

  const wrapFn = (obj, name, sinkName, argIdx) => {
    try {
      const orig = obj[name];
      if (typeof orig !== 'function') return;
      obj[name] = function (...args) {
        try {
          const v = args[argIdx];
          if (typeof v === 'string') record(sinkName, v, { argc: args.length });
        } catch (e) {}
        return orig.apply(this, args);
      };
    } catch (e) {}
  };

  const wrapSetter = (proto, prop, sinkName) => {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set(v) {
          try { record(sinkName, v); } catch (e) {}
          return d.set.call(this, v);
        }
      });
    } catch (e) {}
  };

  // ── 1) HTML-Parsing ─────────────────────────────────────────────
  wrapSetter(Element.prototype, 'innerHTML', 'innerHTML');
  wrapSetter(Element.prototype, 'outerHTML', 'outerHTML');
  wrapFn(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML', 1);
  wrapFn(document, 'write', 'document.write', 0);
  wrapFn(document, 'writeln', 'document.writeln', 0);
  wrapFn(Range.prototype, 'createContextualFragment', 'createContextualFragment', 0);
  wrapFn(DOMParser.prototype, 'parseFromString', 'DOMParser.parseFromString', 0);
  wrapSetter(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');

  // ── 2) Direkte Ausfuehrung ──────────────────────────────────────
  try {
    const origEval = window.eval;
    window.eval = function (v) {
      try { record('eval(indirect)', v); } catch (e) {}
      return origEval(v);
    };
  } catch (e) {}

  try {
    const OrigFunction = window.Function;
    window.Function = new Proxy(OrigFunction, {
      construct(target, args) {
        try { record('Function', args.join(' | ')); } catch (e) {}
        return new target(...args);
      },
      apply(target, thisArg, args) {
        try { record('Function', args.join(' | ')); } catch (e) {}
        return target.apply(thisArg, args);
      }
    });
  } catch (e) {}

  wrapFn(window, 'setTimeout', 'setTimeout(string)', 0);
  wrapFn(window, 'setInterval', 'setInterval(string)', 0);

  // ── 3) Attribute & Properties ───────────────────────────────────
  try {
    const origSetAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      try {
        if (/^on/i.test(name) || /^(href|src|srcdoc|formaction|action|xlink:href|data)$/i.test(name)) {
          record('setAttribute:' + name, value, { tag: this.tagName });
        }
      } catch (e) {}
      return origSetAttr.apply(this, arguments);
    };
  } catch (e) {}

  wrapSetter(HTMLScriptElement.prototype, 'src', 'script.src');
  wrapSetter(HTMLIFrameElement.prototype, 'src', 'iframe.src');
  wrapSetter(HTMLAnchorElement.prototype, 'href', 'a.href');
  wrapSetter(HTMLFormElement.prototype, 'action', 'form.action');

  // ── 4) Navigation / URL-Kontext ─────────────────────────────────
  wrapFn(Location.prototype, 'assign', 'location.assign', 0);
  wrapFn(Location.prototype, 'replace', 'location.replace', 0);
  wrapFn(window, 'open', 'window.open', 0);
  wrapFn(history, 'pushState', 'history.pushState(url)', 2);
  wrapFn(history, 'replaceState', 'history.replaceState(url)', 2);

  // ── 5) Storage-Senken (Stored-XSS-Pfade) ────────────────────────
  try {
    const origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (k, v) {
      try {
        const store = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
        record(store + '.setItem', v, { key: String(k) });
      } catch (e) {}
      return origSetItem.apply(this, arguments);
    };
  } catch (e) {}

  // ── 6) Cookie-Schreibzugriffe ───────────────────────────────────
  try {
    const cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cd && cd.set) {
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        enumerable: cd.enumerable,
        get: cd.get,
        set(v) {
          try { record('document.cookie(set)', v); } catch (e) {}
          return cd.set.call(this, v);
        }
      });
    }
  } catch (e) {}

  // ── 7) Netzwerk-Ausgang (Korrelation API <-> Sink) ──────────────
  try {
    const origFetch = window.fetch;
    window.fetch = function (...a) {
      try {
        const url = typeof a[0] === 'string' ? a[0] : (a[0] && a[0].url) || '<request>';
        const body = a[1] && typeof a[1].body === 'string' ? a[1].body : null;
        record('fetch', url, { method: (a[1] && a[1].method) || 'GET', body: body ? snippet(body) : null });
      } catch (e) {}
      return origFetch.apply(this, a);
    };
  } catch (e) {}

  try {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      try { this.__xh = { method, url: String(url) }; record('xhr.open', String(url), { method }); } catch (e) {}
      return origOpen.apply(this, arguments);
    };
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function (body) {
      try { record('xhr.send', typeof body === 'string' ? body : '<binary>', this.__xh || null); } catch (e) {}
      return origSend.apply(this, arguments);
    };
  } catch (e) {}

  wrapFn(navigator, 'sendBeacon', 'navigator.sendBeacon', 0);

  // ── 8) WebSocket & Worker ───────────────────────────────────────
  try {
    const OrigWS = window.WebSocket;
    window.WebSocket = new Proxy(OrigWS, {
      construct(target, args) {
        try { record('WebSocket(url)', String(args[0])); } catch (e) {}
        const ws = new target(...args);
        const origSend = ws.send;
        ws.send = function (data) {
          try { record('WebSocket.send', data); } catch (e) {}
          return origSend.apply(this, arguments);
        };
        return ws;
      }
    });
  } catch (e) {}

  try {
    const OrigWorker = window.Worker;
    window.Worker = new Proxy(OrigWorker, {
      construct(target, args) {
        try { record('Worker(script)', String(args[0])); } catch (e) {}
        return new target(...args);
      }
    });
  } catch (e) {}

  // ── Helpers ─────────────────────────────────────────────────────
  window.__xssDump = (onlyTainted) => {
    const log = onlyTainted ? window.__xssLog.filter((e) => e.tainted) : window.__xssLog;
    return JSON.stringify(log, null, 1);
  };
  window.__xssClear = () => { window.__xssLog.length = 0; };
  window.__xssMarkers = (list) => { MARKERS.length = 0; MARKERS.push(...list); };

  console.log('[sink-hook v2] aktiv. Marker:', MARKERS.join(', '), '| Dump: __xssDump(true)');
  return 'installed';
})();
