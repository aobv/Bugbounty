# JS-Assets, Source Maps, Endpunkte, Routen

Das Bundle ist die ergiebigste Recon-Quelle: Endpunkte, Routen, Feature-Flags, gelegentlich Secrets — und die Datei, in der später `dom-sink-hooker` die Sinks sucht. Alle Muster unten sind gegen ein minifiziertes Test-Bundle geprüft; Treffer **und** Fehlschläge sind vermerkt, weil die Fehlschläge lehrreicher sind.

## 1 — Assets erfassen (Chromium über Playwright)

Das Modul liegt global, `NODE_PATH` ist deshalb Pflicht:

```bash
NODE_PATH=$(npm root -g) node capture.js https://TARGET/ ./recon-out
```

```javascript
// capture.js — JS-Assets, XHR/fetch-Ziele, Security-Header, CSP aus Header UND <meta>
const { chromium } = require('playwright');
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [url, outDir = 'recon-out'] = process.argv.slice(2);
const UA = 'denibkv-hackerone-research';            // Programm-Vorgabe hat Vorrang
fs.mkdirSync(path.join(outDir, 'js'), { recursive: true });

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ userAgent: UA, ignoreHTTPSErrors: true,
    extraHTTPHeaders: { 'X-Bug-Bounty': UA } });
  const page = await ctx.newPage();
  const assets = [], endpoints = [], headerLog = [];

  page.on('response', async (res) => {
    const req = res.request(), u = res.url(), h = res.headers();
    const ct = (h['content-type'] || '').toLowerCase();
    const isJS = /\.m?js(\?|$)/i.test(u) || ct.includes('javascript') || ct.includes('ecmascript');

    headerLog.push({ url: u, status: res.status(), type: req.resourceType(),
      csp: h['content-security-policy'] || null,
      cspRO: h['content-security-policy-report-only'] || null,
      xfo: h['x-frame-options'] || null, cto: h['x-content-type-options'] || null,
      server: h['server'] || null, setCookie: h['set-cookie'] ? '(vorhanden)' : null,
      location: h['location'] || null, cors: h['access-control-allow-origin'] || null });

    if (['xhr', 'fetch', 'websocket'].includes(req.resourceType()))
      endpoints.push({ method: req.method(), url: u, status: res.status() });

    if (!isJS) return;
    try {                                            // wirft bei Redirects und Cache-Responses
      const body = await res.body();
      const name = crypto.createHash('sha1').update(u).digest('hex').slice(0, 12)
                 + '_' + (u.split('/').pop().split('?')[0] || 'asset');
      fs.writeFileSync(path.join(outDir, 'js', name), body);
      const sm = body.toString('utf8').match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
      assets.push({ url: u, bytes: body.length, file: name, sourceMappingURL: sm ? sm[1] : null });
    } catch (e) { assets.push({ url: u, error: String(e.message) }); }
  });

  await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 });
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)).catch(() => {});
  await page.waitForTimeout(3000);                   // Lazy-Chunks anstossen

  const metaCSP = await page.$$eval('meta[http-equiv="Content-Security-Policy" i]',
                                    els => els.map(e => e.getAttribute('content'))).catch(() => []);
  const inline = await page.$$eval('script:not([src])', els => els.map(e => e.textContent.slice(0, 2000)));
  for (const [f, d] of [['assets', assets], ['headers', headerLog], ['endpoints', endpoints],
                        ['inline-scripts', inline], ['meta-csp', metaCSP]])
    fs.writeFileSync(path.join(outDir, `${f}.json`), JSON.stringify(d, null, 2));
  console.log(`JS-Assets: ${assets.length} | Responses: ${headerLog.length} | ` +
              `XHR/fetch: ${endpoints.length} | meta-CSP: ${metaCSP.length}`);
  await browser.close();
})();
```

Drei Punkte, die nicht optional sind: `try/catch` um `res.body()` (wirft bei Redirects und aus dem Cache bedienten Responses), das Scrollen plus Wartezeit (sonst fehlen die lazy geladenen Chunks und die aus ihnen abgehenden Requests), und das Mitschreiben von Header-CSP **und** Meta-CSP — nur eine Quelle zu lesen unterschlägt eine Schutzschicht.

Minifizierte Bundles vor der Sink-Analyse lesbar machen:

```bash
npx --no-install prettier --parser babel recon-out/js/<datei> > <datei>.pretty.js
```

## 2 — Source Maps finden

| Weg | Prüfung |
|---|---|
| Kommentar im Bundle | `//[#@]\s*sourceMappingURL=(\S+)` |
| Blind probieren | `<bundle>.map`, `<bundle>.js.map` |
| Response-Header | `SourceMap:`, `X-SourceMap:` |
| Dev-Reste | `webpack://` im Bundle suchen — verrät Modulpfade auch ohne `.map` |

## 3 — Source Map rekonstruieren

Eine Source Map ist fremdkontrollierter Input. Ein naives `open(src,'w')` schreibt bei `webpack://a/../../../../etc/evil.js` außerhalb deines Baums — der Traversal-Guard unten ist getestet und Pflicht.

```python
#!/usr/bin/env python3
"""Schreibt sourcesContent einer .map in einen Verzeichnisbaum. Nutzung: unmap.py <map> <outdir>"""
import json, sys, re
from pathlib import Path

def safe_rel(src: str, i: int) -> Path:
    s = re.sub(r'^[a-zA-Z0-9.+-]+://', '', src)          # webpack://, file://, http(s)://
    s = s.replace('\\', '/')
    parts = [p for p in s.split('/') if p not in ('', '.', '..')]
    parts = [re.sub(r'[^A-Za-z0-9._\-]', '_', p) for p in parts]
    return Path(*parts) if parts else Path(f'source_{i}.js')

def main(mapfile, outdir):
    data = json.loads(Path(mapfile).read_text(encoding='utf-8', errors='replace'))
    sources, contents = data.get('sources') or [], data.get('sourcesContent') or []
    root = Path(outdir).resolve(); n = 0
    if not contents:
        print('sourcesContent fehlt - nur Pfadliste verwertbar:')
        for s in sources: print(' ', s)
        return
    for i, src in enumerate(sources):
        body = contents[i] if i < len(contents) else None
        if body is None: continue
        dest = (root / safe_rel(src, i)).resolve()
        if not str(dest).startswith(str(root)):          # Traversal-Guard
            dest = root / f'unsafe_{i}.js'
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding='utf-8'); n += 1
    print(f'{n}/{len(sources)} Quellen -> {root}')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
```

Zweiter Fall, der abgefangen werden muss: `sourcesContent` fehlt oder einzelne Einträge sind `null`. Dann bleibt die Pfadliste — sie allein verrät Verzeichnisstruktur, interne Modulnamen und oft ungenutzte Admin-Routen.

## 4 — Endpunkte extrahieren

| Muster | Regex |
|---|---|
| quoted-path | ``['"`](/[A-Za-z0-9_\-./{}:$]{2,120})['"`]`` |
| abs-url | ``['"`](https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./{}:$?=&%]*)?)['"`]`` |
| ws-url | ``['"`](wss?://[A-Za-z0-9._\-]+(?:/[^'"`]*)?)['"`]`` |
| fetch-Aufruf | ``\bfetch\s*\(\s*['"`]([^'"`]+)`` |
| baseURL | ``\bbaseURL\s*[:=]\s*['"`]([^'"`]+)`` |
| HTTP-Methode auf beliebigem Bezeichner | ``\b[A-Za-z_$][\w$]*\s*\.\s*(get\|post\|put\|patch\|delete\|request\|head)\s*\(\s*['"`]([^'"`]+)`` |

**Der wichtigste Befund:** ein Muster, das auf sprechende Bezeichner setzt (`axios|http|api|client` vor `.post(`), liefert im minifizierten Bundle **null** Treffer — die Namen sind wegminifiziert (`a.post(...)`, `e.get(...)`). Die letzte Zeile lässt jeden Bezeichner zu und findet damit auch `POST /orders/checkout` und `GET /internal/admin/flags`. Preis ist Rauschen (`.get()` auf Maps) — billiger als ein verpasster Endpunkt.

```bash
grep -oPh "\b[A-Za-z_\$][\w\$]*\s*\.\s*(get|post|put|patch|delete|request|head)\s*\(\s*['\"\`][^'\"\`]+" \
  recon-out/js/* | sort -u
```

## 5 — Secrets

| Typ | Regex |
|---|---|
| Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` |
| AWS Access Key ID | `\b(?:AKIA\|ASIA\|AGPA\|AIDA\|AROA\|ANPA)[0-9A-Z]{16}\b` |
| GitHub Token | `\b(?:ghp\|gho\|ghu\|ghs\|ghr\|github_pat)_[0-9A-Za-z_]{20,}\b` |
| Stripe Key | `\b(?:sk\|pk\|rk)_(?:live\|test)_[0-9A-Za-z]{10,}\b` |
| JWT | `\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b` |
| generische Zuweisung | `(?i)\b(api[_-]?key\|secret\|passwd\|password\|token\|auth)\s*[:=]\s*['"][A-Za-z0-9_\-!@#$%^&*]{12,}['"]` |

Die generische Zuweisung ist syntaktisch korrekt, trifft im minifizierten Bundle aber **null** — sie gehört auf Config-Blobs, `<script type="application/json">`, `__NEXT_DATA__` und rekonstruierte Source-Map-Quellen, nicht auf das Bundle.

Jeder Treffer ist ein **Kandidat, kein Finding**: erst Gültigkeit und Impact im Rahmen der Programmregeln klären, und niemals fremde Credentials benutzen.

## 6 — Routen aus dem SPA-Bundle

| Framework / Form | Regex |
|---|---|
| React Router, Objekt-Config | ``\bpath\s*:\s*['"`]([^'"`]+)['"`]`` |
| generisch, nur absolute Pfade | ``\bpath\s*[:=]\s*['"`](/[^'"`]*)['"`]`` |
| kompiliertes JSX | ``createElement\(\s*[A-Za-z_$][\w$]*\s*,\s*\{[^}]*?\bpath\s*:\s*['"`]([^'"`]+)`` |
| Vue Router | ``\{\s*path\s*:\s*['"`]([^'"`]+)['"`]\s*,\s*(?:name\|component)\s*:`` |
| Next.js-Indikator | `\b__NEXT_DATA__\b\|\bbuildId\b\|/_next/static/` |

Routen mit Parameter-Segmenten (`:orderId`, `[id]`) zuerst — dort landet fremder Input. Ohne Regex ergänzend: bei Next.js listet `/_next/static/<buildId>/_buildManifest.js` die Routen direkt, bei Webpack listet die Chunk-Map (`{1:"chunk-a",2:"chunk-b"}`) die lazy geladenen Bereiche, die man sonst nie besucht. Beides am Target verifizieren, nicht annehmen.

## 7 — Übergabe

Bundles, `.pretty.js`-Fassungen und rekonstruierte Quellen liegen in `evidence/<target>/recon/`. Sink-Suche, Source-Suche und Taint-Tracing macht ab hier `dom-sink-hooker` — die Stacktraces der Hooks zeigen Datei und Zeile, und die pretty-gedruckte Fassung macht sie lesbar. Erkennst du im Bundle einen Sanitizer, geht es mit `waf-sanitizer-playbook/references/dompurify.md` weiter.
