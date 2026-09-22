// dom-sink-hooker — source-watch.js
// Protokolliert Source-Lesezugriffe: URLSearchParams, JSON.parse, Storage-Reads, Cookie-Reads, window.name.
// Gegenstueck zu sink-hook.js: damit laesst sich der komplette Pfad Source -> Sink aus zwei Logs korrelieren.

(() => {
  if (window.__srcWatchInstalled) return 'already installed';
  window.__srcWatchInstalled = true;

  const MARKERS = (window.__XSS_MARKERS || ['DX_XSS', 'xss7q3z']);
  const MAXLEN = 300;
  const MAXLOG = 5000;
  window.__srcLog = [];

  const snippet = (v) => {
    let s;
    try { s = typeof v === 'string' ? v : JSON.stringify(v); } catch (e) { try { s = String(v); } catch (e2) { s = '<unserializable>'; } }
    return s.length > MAXLEN ? s.slice(0, MAXLEN) + '...[truncated]' : s;
  };

  const tainted = (s) => MARKERS.some((m) => s.includes(m));

  const record = (source, value, extra) => {
    try {
      if (window.__srcLog.length >= MAXLOG) return;
      const sn = snippet(value);
      const entry = { t: new Date().toISOString(), source, tainted: tainted(sn), value: sn, extra: extra || null, stack: (new Error()).stack || null };
      window.__srcLog.push(entry);
      if (entry.tainted) console.warn('[source-watch] TAINTED READ <-', source, sn);
    } catch (e) {}
  };

  // URLSearchParams
  try {
    for (const m of ['get', 'getAll', 'has']) {
      const orig = URLSearchParams.prototype[m];
      URLSearchParams.prototype[m] = function (key) {
        const r = orig.apply(this, arguments);
        try { record('URLSearchParams.' + m, r, { key: String(key) }); } catch (e) {}
        return r;
      };
    }
  } catch (e) {}

  // JSON.parse (häufig Zwischenschritt zwischen Source und Sink)
  try {
    const origParse = JSON.parse;
    JSON.parse = function (text, reviver) {
      const r = origParse.apply(this, arguments);
      try {
        const sn = snippet(text);
        if (tainted(sn)) record('JSON.parse', sn);
      } catch (e) {}
      return r;
    };
  } catch (e) {}

  // Storage-Reads
  try {
    const origGet = Storage.prototype.getItem;
    Storage.prototype.getItem = function (k) {
      const r = origGet.apply(this, arguments);
      try {
        const store = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
        if (r !== null) record(store + '.getItem', r, { key: String(k) });
      } catch (e) {}
      return r;
    };
  } catch (e) {}

  // Cookie-Reads
  try {
    const cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (cd && cd.get) {
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        enumerable: cd.enumerable,
        get() {
          const r = cd.get.call(this);
          try { record('document.cookie(get)', r); } catch (e) {}
          return r;
        },
        set: cd.set
      });
    }
  } catch (e) {}

  // window.name
  try {
    const wn = Object.getOwnPropertyDescriptor(window, 'name');
    let nameVal = window.name;
    Object.defineProperty(window, 'name', {
      configurable: true,
      get() { try { record('window.name(get)', nameVal); } catch (e) {} return nameVal; },
      set(v) { try { record('window.name(set)', v); } catch (e) {} nameVal = v; }
    });
    void wn;
  } catch (e) {}

  // Snapshot aller aktuellen Source-Werte (nicht hookbar, daher Momentaufnahme)
  window.__srcSnapshot = () => {
    const snap = {};
    try { snap['location.href'] = location.href; } catch (e) {}
    try { snap['location.search'] = location.search; } catch (e) {}
    try { snap['location.hash'] = location.hash; } catch (e) {}
    try { snap['location.pathname'] = location.pathname; } catch (e) {}
    try { snap['document.referrer'] = document.referrer; } catch (e) {}
    try { snap['window.name'] = window.name; } catch (e) {}
    try {
      snap['localStorage'] = {};
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        snap['localStorage'][k] = snippet(localStorage.getItem(k));
      }
    } catch (e) {}
    try {
      snap['sessionStorage'] = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        snap['sessionStorage'][k] = snippet(sessionStorage.getItem(k));
      }
    } catch (e) {}
    try {
      for (const id of ['__NEXT_DATA__', '__NUXT__']) {
        const el = document.getElementById(id);
        if (el) snap['#' + id] = snippet(el.textContent);
      }
    } catch (e) {}
    const taintedKeys = Object.entries(snap).filter(([, v]) => tainted(typeof v === 'string' ? v : JSON.stringify(v)));
    if (taintedKeys.length) console.warn('[source-watch] TAINTED SNAPSHOT:', taintedKeys.map(([k]) => k).join(', '));
    return JSON.stringify(snap, null, 1);
  };

  window.__srcDump = (onlyTainted) => {
    const log = onlyTainted ? window.__srcLog.filter((e) => e.tainted) : window.__srcLog;
    return JSON.stringify(log, null, 1);
  };

  console.log('[source-watch] aktiv. Dump: __srcDump(true) | Snapshot: __srcSnapshot()');
  return 'installed';
})();
