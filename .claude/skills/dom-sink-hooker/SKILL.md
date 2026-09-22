---
name: dom-sink-hooker
description: Browser-Instrumentation für DOM-XSS-Analyse und lückenloses Taint-Tracking. Hookt alle relevanten JS-Sinks (HTML-Parsing, Code-Ausführung, Attribute, Navigation, Storage, Netzwerk) sowie postMessage und Source-Lesezugriffe im Seitenkontext und loggt jeden Aufruf mit Stacktrace, Wert-Vorschau und Taint-Marker. Verwenden bei jeder DOM-XSS-Analyse, bei Source→Sink-Verfolgung in minifizierten Bundles, bei postMessage-Audits und immer dann, wenn die Frage ist, ob und wo ein kontrollierter Wert in einer Sink landet. Pflicht-Werkzeug in den Phasen Sink-Inventar, Source-Inventar und Taint-Tracing. Die Instrumentierung dient nur der Analyse — ein durch Hooks künstlich erzeugter Zustand ist niemals ein Finding.
---

# dom-sink-hooker

Grundregel: Du rätst nie über Datenflüsse. Du beobachtest sie. Jede Aussage "Wert X landet in Sink Y" ohne Log-Eintrag ist eine Vermutung und damit verboten.

## Snippets

- `assets/hooks/sink-hook.js` — alle Sinks: HTML-Parsing, Code-Ausführung, Attribute, Navigation, Storage, Netzwerk-Ausgang, Worker. Log: `window.__xssLog`
- `assets/hooks/postmessage-watch.js` — message-Listener (inkl. Funktionsquelltext für Origin-Check-Analyse), `onmessage`-Zuweisungen, ein-/ausgehende postMessage. Log: `window.__pmLog`
- `assets/hooks/source-watch.js` — Source-Lesezugriffe: URLSearchParams, JSON.parse, localStorage/sessionStorage.getItem, document.cookie, window.name. Log: `window.__srcLog`

## Pflicht-Workflow

1. **Injizieren, bevor irgendetwas passiert.** Snippet-Datei lesen, im Seitenkontext ausführen (Konsole / evaluate_script). Reihenfolge: sink-hook.js, dann source-watch.js, dann postmessage-watch.js.
2. **Marker setzen.** Standard: `DX_XSS`, `xss7q3z`. Eigene per `__xssMarkers(['m1','m2'])`. Marker alphanumerisch halten, damit Encoding-Schichten sie nicht zerstören.
3. **Marker in die Source bringen** und den Flow normal durchlaufen. Keine künstlichen Zustände.
4. **Auswerten:** `__xssDump(true)` (nur tainted), `__srcDump(true)` (tainted Source-Lesungen), `__pmDump()` (postMessage). Vollständige Logs: jeweils ohne Argument.
5. **Dokumentieren:** Pro tainted Treffer Sink + Wert + Stacktrace → Kandidaten-Matrix (Datei:Zeile steht im Stack).
6. **Nach harter Navigation sofort neu injizieren.** SPA-Routenwechsel ohne Reload behalten die Hooks.

## Situation → Aktion

| Situation | Aktion |
|---|---|
| Hooks feuern nicht, obwohl die Aktion sichtbar passiert | siehe `references/troubleshooting.md` Abschnitt 1 (App hat native Referenzen vor Injection gecacht, Worker, iframe, Trusted Types) |
| Stack zeigt nur minifizierte Ein-Zeilen-Frames | Abschnitt 2 (Pretty Print, Source Maps, Blackboxing) |
| Marker kommt nirgendwo an | Abschnitt 3 (Encoding-Kette, einfacheren Marker wählen, mehrere Marker parallel) |
| Log überläuft / Seite wird träge | Abschnitt 4 (`__xssClear()`, nur tainted dumpen, Scope der Hooks eingrenzen) |
| Cross-Origin-iframe auf der Seite | Abschnitt 5 (DevTools-Kontext auf den Frame wechseln, dort injizieren) |
| Jede Navigation killt die Hooks | Abschnitt 6 (CDP `Page.addScriptToEvaluateOnNewDocument`, sonst Re-Injection-Routine) |
| Site hat Debugger-/Tamper-Erkennung | Abschnitt 7 (Minimal-Instrumentierung, nur benötigte Hooks) |
| Wert stammt nicht aus einer Source, sondern aus einem Options-/Config-Objekt | `references/prototype-pollution.md` — Pollution, Gadget und Opferpfad getrennt belegen |
| Markup kommt durch, aber Attribute und Handler werden gestrippt | `references/dom-clobbering.md` — `id`/`name` gegen Globals und Config-Properties |

## Helper-API

`__xssDump(onlyTainted?)` · `__xssClear()` · `__xssMarkers([...])` · `__srcDump(onlyTainted?)` · `__srcSnapshot()` (aktueller Wert aller Sources) · `__pmDump()`

## Harte Grenzen

- Ein Log-Treffer ist eine Beobachtung, kein Finding. Finding erst bei beobachteter Ausführung im Opferkontext.
- Nicht hookbar: `location.href`-Zuweisung, direkte `eval()`-Aufrufe im selben Scope, `on*`-Property-Zuweisungen pro Element. Für diese drei: Network-Tab, Haltepunkte und manuelle Prüfung.
- Log: max. 5000 Einträge, Werte auf 300 Zeichen gekürzt.
