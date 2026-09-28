# Live Nation / Ticketmaster — Offline-Sink-Analyse

Stand 2026-09-28. Diese Runde ist **ohne einen einzigen Request gegen ein
In-Scope-Ziel** entstanden. Was das für die Belastbarkeit heißt, steht unten.

## Netz: warum nichts live verifiziert ist

Der Container, in dem diese Analyse lief, hat keinen Egress zu den Zielen. Der
Egress-Proxy verweigert `CONNECT` für **jeden** externen Host — gegengeprüft mit
einem neutralen Kontrollhost:

```
ticketmaster.com:443 — connect_rejected (organization policy)
example.com:443      — connect_rejected (organization policy)
```

Erreichbar sind nur die Paket-Quellen (`registry.npmjs.org`, `github.com`). Die
uniformen `HTTP/1.1 403` mit `Content-Type: text/plain`, die ein erster Header-Sweep
über alle 22 Hosts lieferte, kamen daher **vom Proxy, nicht von Akamai** — sie
sagen über die Ziele nichts aus und dürfen nicht als Fingerprint gelesen werden.

Folge: Kein CSP-Inventar, keine Live-Bundles, keine Source-Maps von den Zielen,
keine Reflection-Tests, kein Sink-Trigger. **Ein feuerbares XSS ist von hier aus
nicht auffindbar** — feuerbar heißt im Browser auf dem Ziel-Origin ausgelöst, und
dieser Schritt fehlt vollständig.

## Was stattdessen analysiert wurde

Ticketmaster publiziert Teile seines Frontends öffentlich. Das ist echter Code,
der auf den In-Scope-Origins laufen kann, und er war erreichbar:

| Quelle | Version | Umfang | Relevanz |
|---|---|---|---|
| `@ticketmaster/aurora` (npm) + `ticketmaster/aurora` (GitHub) | 3.151.0 | 360 JS-Dateien, 8.5 MB | **hoch** — „Shared UI Library for Ticketmaster", Versionsstand 3.151.0 spricht für breiten Produktiveinsatz |
| `@ticketmaster/allure-core` / `allure-ui` | 6.0.15 | 121 JS-Dateien | **keine** — s. u. |
| `ticketmaster-venue-widget` | 1.3.20 | 5 JS-Dateien | **keine** — Drittanbieter (`github.com/wolfazoid`), kein TM-Asset |

Scanner: `sink_scan.py` aus `xss-sink-recon` über 1005 Dateien, `--min-score 0`.
54 Kandidaten roh, davon nach Triage **0 verwertbare HTML-Injection-Sinks**.

### allure-* fällt aus dem Scope

Die Top-Scores des Scanners (73/70) landeten alle in `allure-core`. Beim Lesen
löst sich das auf: `allure-core` ist Ticketmasters **interne** Tools-Library —
Okta-Auth, `sessionStorage`-Token, und Redirect-Ziele die auf `tmtools`-Hostnames
prüfen (`dist/index.esm.js:1841`). `*.tmtools.ticketmaster.com` steht **nicht** in
der 22-Host-Liste. Out of scope, unabhängig von der Code-Qualität.

Die Treffer selbst waren zudem kein XSS: `router.push(url.toString())` mit einem
aus `window.location.hostname` gebauten Ziel, und `window.location.replace()` mit
festem `origin` + `pathname` (`index.esm.js:1335`). Redirect-Sinks, keine
Script-Ausführung.

### Die Score-70-Treffer in aurora sind Fehlalarme

`npm-aurora-3.151.0/package/dist/index.umd.min.js` liefert `jquery-factory <-
message-data` und `jquery-factory <- tainted-variable`. Beides falsch:

```
sink_snippet: ...Y.easing.easeInOutQuad,$("primary","base"),function(e){...
```

Das `$` ist ein minifizierter styled-components-Theme-Helper, nicht jQuery. Ein
`grep` über das Bundle nach `jQuery|jquery` findet **null** Treffer; jQuery ist
nicht gebündelt. Die `message-data`-Quelle ist derselbe Variablen-Kollisions-Effekt
in minifiziertem Code. Genau die Fehlalarm-Form, die `references/triage.md`
beschreibt — in Minifikat sind Ein-Zeichen-Namen bedeutungslos.

### aurora ist bei HTML-Injection sauber

Gegen den unminifizierten Source (GitHub `src/` + npm `lib/`) geprüft:

- `dangerouslySetInnerHTML` — **0 Treffer**
- `innerHTML` / `outerHTML` / `insertAdjacentHTML` — nur in `__tests__`
  (`expect(container.innerHTML).toMatchSnapshot()`), kein Produktivpfad
- `eval` / `new Function` / `srcDoc` — **0 Treffer**
- `postMessage` / `addEventListener("message")` — **0 Treffer**

Für eine React-Design-System-Library ist das der erwartbare und korrekte Zustand:
React escapet Text-Children, und die eine Ausnahme ist nicht vorhanden.

## Die eine reale Sink-Klasse: `href`-Durchleitung ohne Scheme-Validierung

Das ist das einzige belastbare Ergebnis dieser Runde.

Acht aurora-Komponenten reichen einen `href`/`url`-Prop **unverändert** an ein
`<a>`-Element weiter:

| Datei | Zeile |
|---|---|
| `src/components/Text/Link.js` | 87 |
| `src/components/Text/LinkCta.js` | 132 |
| `src/components/Link/ListItem.js` | 44 |
| `src/components/List/SectionItem.js` | 74 |
| `src/components/List/RowOptionsLink.js` | 68 |
| `src/components/List/RowContent.js` | 309 |
| `src/components/Breadcrumbs/BreadcrumbItem.js` | 43 |
| `src/components/NavBar/ButtonBase.js` | 72 |
| `src/components/NavBar/Buttons.js` | 25 |

Im gesamten `src/` existiert **keine** Scheme- oder Protokoll-Prüfung. Ein `grep`
über `javascript:`, `vbscript`, `data:text`, `protocol`, `scheme`, `sanitize`,
`purify`, `new URL(` liefert genau zwei Treffer, und beide sind unbeteiligt:
`LazyLoader/helpers.js:10` (`new Url(src)` für Bild-URLs) und
`utils/createParams.js:5` (`encodeURIComponent` beim Query-Bau).

Was `Text/Link.js` an Validierung *hat*, adressiert etwas anderes:
`getRelByTarget()` setzt `rel="noopener"` bei `target="_blank"` — Tabnabbing, nicht
Scheme-Filterung. Die Härtung ist also bewusst gebaut, aber am Scheme vorbei.

**Warum das ein Sink ist:** React sanitisiert `href` nicht. Seit 16.9 gibt es eine
Warnung im Development-Build, im Production-Build wird das Attribut gerendert.
aurora deklariert `react: ">=16"` als Peer-Dependency, deckt also auch Versionen
ab, in denen nichts blockt. Ein `href="javascript:..."` wird damit zu einem
Ein-Klick-XSS im Origin der einbettenden Seite.

**Warum das noch kein Finding ist:** Der Sink liegt in der Library, der Taint
kommt vom Consumer. Die Lücke existiert erst, wenn eine Seite auf einem
In-Scope-Origin einen angreiferkontrollierten Wert in einen dieser Props gibt —
ein `?url=`/`?redirect=`/`?next=`-Parameter, ein API-Feld, ein CMS-Feld. Das ist
genau der Schritt, der ohne Netz nicht prüfbar ist.

Als Hypothese ist sie aber scharf und billig zu testen: die Verifikations-Schritte
stehen in `recon/verify-href-sink.md`.

## Ehrliche Bilanz

- Feuerbares XSS gefunden: **nein**.
- Ausgeschlossen: HTML-Injection-Sinks in aurora (dem wahrscheinlichsten
  gemeinsamen Frontend-Code der Consumer-Origins). Das ist ein negatives
  Ergebnis mit Wert — es nimmt eine ganze Fläche aus der Suche.
- Offen und aussichtsreich: die `href`-Klasse oben, plus alles was nur live
  sichtbar ist (CSP, Reflections, Source-Maps der echten Bundles,
  `postMessage`-Handler der App-Origins).
