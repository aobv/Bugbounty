// dom-sink-hooker — postmessage-watch.js (v2)
// Zeichnet message-Listener (inkl. Funktionsquelltext), onmessage-Zuweisungen
// sowie ein-/ausgehende postMessage-Aufrufe auf.
// Ziel: Origin-/Source-Pruefungen finden und ihre Umgehbarkeit beurteilen.

(() => {
  if (window.__pmWatchInstalled) return 'already installed';
  window.__pmWatchInstalled = true;
  window.__pmLog = [];

  const rec = (type, data) => {
    try { window.__pmLog.push({ t: new Date().toISOString(), type, ...data }); } catch (e) {}
  };

  // Registrierte message-Listener aufzeichnen (Funktionsquelltext zeigt die Origin-Pruefung)
  try {
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
      try {
        if (type === 'message' && typeof fn === 'function') {
          rec('listener-registered', { fnSource: String(fn).slice(0, 500) });
        }
      } catch (e) {}
      return origAdd.apply(this, arguments);
    };
  } catch (e) {}

  // Direkte onmessage-Zuweisungen
  try {
    let handler = window.onmessage;
    Object.defineProperty(window, 'onmessage', {
      configurable: true,
      get() { return handler; },
      set(fn) {
        try { rec('onmessage-assigned', { fnSource: String(fn).slice(0, 500) }); } catch (e) {}
        handler = fn;
      }
    });
  } catch (e) {}

  // Ausgehende postMessage
  try {
    const origPost = window.postMessage;
    window.postMessage = function (msg, origin, transfer) {
      try {
        let preview;
        try { preview = JSON.stringify(msg); } catch (e) { preview = '<unserializable>'; }
        rec('outgoing', { targetOrigin: String(origin), dataPreview: preview ? preview.slice(0, 300) : null });
      } catch (e) {}
      return origPost.apply(this, arguments);
    };
  } catch (e) {}

  // Eingehende Nachrichten (passiv, zusaetzlich zu App-Listenern)
  try {
    window.addEventListener('message', (e) => {
      try {
        let preview;
        try { preview = JSON.stringify(e.data); } catch (err) { preview = '<unserializable>'; }
        rec('incoming', { origin: e.origin, dataPreview: preview ? preview.slice(0, 300) : null });
      } catch (err) {}
    });
  } catch (e) {}

  window.__pmDump = () => JSON.stringify(window.__pmLog, null, 1);
  console.log('[pm-watch v2] aktiv. Dump: __pmDump()');
  return 'installed';
})();
