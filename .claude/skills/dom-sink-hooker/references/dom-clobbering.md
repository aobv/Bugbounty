# DOM Clobbering

Grundregel: Clobbering führt nichts aus. Es legt einen Wert an eine Stelle, an der Code einen erwartet und nicht prüft, woher er kommt. Der Befund ist erst vollständig, wenn dieser Wert in einer Sink landet und dort im Opferkontext ausgeführt wird.

## 1. Mechanik

Der Browser legt für benannte Elemente globale Referenzen an. Du brauchst dafür kein Script und keinen Event-Handler — nur `id` und `name`.

| Markup | Ergebnis |
|---|---|
| `<div id=CFG>` | `window.CFG` ist das Element (überschreibt eine noch nicht zugewiesene globale Variable) |
| `<iframe name=CFG>` · `<object name=CFG>` · `<embed name=CFG>` · `<img name=CFG>` · `<form name=CFG>` | zusätzlich benannter Zugriff über `document.CFG` |
| `<div id=CFG><div id=CFG>` | `window.CFG` wird zur HTMLCollection — indizierbar (`CFG[0]`, `CFG[1]`) und über `id`/`name` der Mitglieder benannt ansprechbar |
| `<form id=CFG><input name=flag></form>` | `CFG.flag` ist das Input-Element (benannter Zugriff über `form.elements`, gilt für Formular-Controls) |
| `<a id=CFG href="URL">` | `CFG` in String-Kontext liefert die href — der einzige bequeme Weg, einen **String** statt eines Element-Objekts zu liefern |
| `<a id=CFG><a id=CFG name=url href="URL">` | zwei Ebenen: `CFG` ist die Collection, `CFG.url` das zweite Anchor-Element, `String(CFG.url)` die href |

Harte Punkte, die in der Praxis beißen:

- Ein geclobbertes Ziel ist ein **Element**, kein String. In String-Kontexten wird daraus `[object HTMLDivElement]` — wertlos. Deshalb ist die Anchor-Variante der Normalfall, sobald der Code den Wert als Zeichenkette verwendet.
- Die href wird beim Serialisieren gegen die Basis-URL aufgelöst. Ob ein Schema wie `javascript:` die Serialisierung unverändert übersteht, **im konkreten Kontext testen**, nicht annehmen.
- Clobbering greift nur gegen Ziele, die zum Lesezeitpunkt noch nicht gesetzt sind. Ein `const CFG = {...}` weiter oben im Bundle gewinnt immer. Reihenfolge prüfen.
- Tiefer als zwei Ebenen: im Einzelfall probieren und das Ergebnis notieren, nicht aus der Tabelle ableiten.

## 2. Ziel → Markup

`MARKER` = `alert('DX_XSS@'+location.origin)`, Konvention wie in `../../waf-sanitizer-playbook/references/payload-ladders.md`.

| Was der Code liest | Markup | Wirkung |
|---|---|---|
| `if (window.CFG)` — Existenzprüfung | `<div id=CFG>` | Prüfung wird truthy, unsicherer Zweig öffnet |
| `if (!CFG.sanitize)` — Flag-Prüfung | `<form id=CFG><input name=sanitize></form>` | Flag ist truthy statt undefined; umgekehrt: fehlt das Input, bleibt es undefined |
| `el.src = CFG.url` — String erwartet | `<a id=CFG><a id=CFG name=url href="URL">` | kontrollierter String in `script.src`/`iframe.src` |
| `location = CFG.next` | dieselbe Anchor-Variante | kontrollierte Navigation, `javascript:`-Schema testen |
| `var base = window.BASE_URL \|\| '/'` | `<a id=BASE_URL href="URL">` | Loader lädt von fremder Origin |
| `CFG.template` in `innerHTML` | Anchor-Variante | href-String wird als Markup geparst |
| Sanitizer-Config aus einer globalen Variable | `<form id=CFG><input name=ALLOWED_TAGS></form>` | Filter-Logik gegen sich selbst wenden (siehe Abschnitt 4) |

Ziele findest du nicht durch Raten: Bundle mit `npx --no-install prettier --parser babel BUNDLE.js > BUNDLE.pretty.js` lesbar machen und nach Lesezugriffen auf Globals suchen. PCRE, also `grep -P` — unter `grep -E` ist `[\w$]` die Zeichenmenge `\`, `w`, `$` und das Muster läuft ins Leere:

```bash
# Globals in Grossschreibung, der uebliche Config-Namensstil
grep -nP 'window\.[A-Z][\w$]*' BUNDLE.pretty.js
# Defaults, bei denen ein fehlendes Global gratis durch einen String ersetzt wird
grep -nP "\|\|\s*['\"/]" BUNDLE.pretty.js
grep -nP "\?\?\s*['\"/]" BUNDLE.pretty.js
```

## 3. Typische Angriffspunkte

- **Filter-/Sanitizer-Logik**, die ihre Konfiguration aus einer globalen Variable zieht.
- **Script- und Asset-Loader**, die Basis-Pfad oder `src` aus einer Config lesen.
- **Feature-Flags und Kill-Switches** (`debug`, `allowUnsafe`, `sanitize`), die nur auf Existenz geprüft werden.
- **Fallback-Defaults** nach dem Muster `window.X && window.X.y || '/default'` — dort ist der geerbte Wert gratis.
- **Analytics-/Consent-Stubs**, die vor dem eigentlichen Script als Globals erwartet werden.

## 4. Wann Clobbering überhaupt das richtige Werkzeug ist

Genau dann, wenn **Markup durchkommt, aber Attribute und Handler gestrippt werden** — der klassische Sanitizer-Rest. `id` und `name` stehen auf fast jeder Allowlist, weil sie für sich harmlos aussehen.

- Ist das die Lage, steht die Klasse als Filter-Bypass bereits in `../../waf-sanitizer-playbook/references/bypass-map.md`, Abschnitt "Strukturelle Umgehungen". Dort ist sie der Angriff auf die Filter-Logik; hier ist sie Source-Inventar. Querverweisen, nicht doppelt führen.
- Ob die Sanitizer-Config `id`/`name` durchlässt, gehört zur Config-Analyse: `../../waf-sanitizer-playbook/references/dompurify.md`, Abschnitt 2.
- Zählt als eigene Technik-Klasse im Persistenz-Mindestmaß. Blockiert der Filter `id`, ist die Leiter: `name` statt `id` · anderes Element (`form`, `iframe`, `object`, `embed`, `img`) · Collection-Variante mit doppeltem Bezeichner · Anchor für den String-Fall.

## 5. Nachweis mit den Hooks

1. Marker vor der Injektion setzen: `window.__XSS_MARKERS = ['DX_XSS','xss7q3z']`. `__xssMarkers()` ändert nur das Array von `sink-hook.js` und lässt `source-watch.js` auf den Defaults.
2. Injektionsreihenfolge wie in `../SKILL.md`: `../assets/hooks/sink-hook.js` → `../assets/hooks/source-watch.js` → `../assets/hooks/postmessage-watch.js`. Jede Datei genau einmal.
3. Marker in den geclobberten Wert legen, nicht in den Bezeichner: `<a id=CFG><a id=CFG name=url href="https://example.invalid/xss7q3z">`.
4. Markup über den **echten Eingabepfad** einbringen (Kommentarfeld, Profilname, Parameter) — nicht per Konsole ins DOM schreiben.
5. `__xssDump(true)` auswerten: ein tainted Eintrag auf `script.src`, `setAttribute:src`, `a.href`, `innerHTML`, `fetch` oder `location.assign` belegt, dass der geclobberte Wert die Sink erreicht.
6. **Grenze:** Das Lesen einer globalen Variable ist nicht hookbar. Die Hooks zeigen das Ankommen des Wertes, nicht den Lesezugriff. Wer sehen will, ob ein Global überhaupt gelesen wird, kann vor dem App-Start einen Getter darauf legen (`Object.defineProperty(window,'CFG',{configurable:true,get(){console.trace();}})`) — das ist reine Analyse und nie Teil eines Findings.
7. Feuert nichts, obwohl das Markup sichtbar im DOM steht: `troubleshooting.md` Abschnitt 1 (gecachte Referenzen, Worker, iframe, Trusted Types) abarbeiten.

## 6. Nachweis-Regel und Verbote

- **Verboten:** ein Finding aus Konsolen-Zustand. Ein im DevTools eingefügtes `<a id=CFG>` beweist nichts über die Anwendung.
- **Verboten:** aus "`window.CFG` ist jetzt ein Element" auf XSS schließen. Geclobbertes Global ohne Sink-Log ist eine Beobachtung, kein Kandidat mit Impact.
- Finding erst bei beobachteter Ausführung im Opferkontext mit Origin-Marker und Screenshot.
- Sauber geschlossen wird so: "Markup durchgelassen, `id`/`name` erlaubt, N Ziele aus Abschnitt 2 gegen das Bundle geprüft, kein Global ohne vorherige Zuweisung" — mit den geprüften Zielen. Auch das ist ein verwertbares Ergebnis.
- Gespeichertes Clobbering-Markup ist Stored Content: nach dem Test entfernen.
