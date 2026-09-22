# Troubleshooting — Situation → konkrete Aktion

## 1. Hooks feuern nicht, obwohl die Aktion sichtbar passiert

Mögliche Ursachen, in Prüfreihenfolge:

1. **App hat native Referenzen vor der Injection gecacht** (z. B. `const ih = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set` oder `const _fetch = window.fetch` beim Laden). → Hooks früher injizieren: vor dem App-Start, ggf. über CDP `Page.addScriptToEvaluateOnNewDocument` (Abschnitt 6). Wenn das nicht geht: im Bundle nach der Cache-Stelle suchen und den Kandidaten über statische Analyse belegen.
2. **Code läuft in einem Worker.** → Hooks dort injizieren (Worker-Kontext in DevTools wählen). `sink-hook.js` loggt Worker-Erzeugung (`Worker(script)`) — prüfen, ob die App welche startet.
3. **Code läuft in einem iframe.** → DevTools-Kontext auf den Frame umstellen (Dropdown oben in der Konsole), dort injizieren. Pro Frame ein Log.
4. **Trusted Types aktiv.** → Bei TT schlägt die String-Zuweisung an die Sink fehl, bevor der Hook sieht — Symptom: TypeError in der Konsole. Das ist kein Hook-Fehler, sondern ein Befund (TT greift). Dokumentieren, dann die TT-Strategie aus dem Hunt-Prompt fahren (Default-Policy, Policy-Lücken).
5. **Sink steht nicht in der Hook-Liste.** → `location.href`-Zuweisung und `on*`-Property-Zuweisungen sind nicht hookbar. Für diese: Haltepunkt im Bundle oder Network-Beobachtung.

## 2. Stack zeigt nur minifizierte Ein-Zeilen-Frames

1. Sources-Tab: Pretty Print ( `{}` ) aktivieren.
2. DevTools-Settings: Source Maps einschalten. Wenn die App `.map` ausliefert, zeigt der Stack Original-Datei:Zeile — das ist der Normalfall und der Grund, warum Phase 1 Source Maps prüft.
3. Keine Maps: die Datei in der Stackzeile direkt öffnen, Zeile/Spalte anspringen, den umgebenden minifizierten Block lesen. Sink-Aufrufstellen sind auch minifiziert erkennbar (`.innerHTML=`, `.setAttribute(`).
4. Frames als "anonymous" oder `<anonymous>`: der Aufruf kam aus dynamisch erzeugtem Code (eval/Function/Template) — im Log-Eintrag den Wert prüfen, er enthält oft den Generator-Hinweis.

## 3. Marker kommt nirgendwo an

1. Encoding-Kette prüfen: Wird der Marker URL-dekodiert, HTML-entkodiert, JSON-geparst, bevor er gelesen wird? `__srcSnapshot()` und `__srcDump()` zeigen, was die App tatsächlich liest.
2. Marker vereinfachen: rein alphanumerisch (`xss7q3z`) — überlebt jede Encoding-Schicht.
3. Mehrere Marker parallel in verschiedene Sources (`__xssMarkers(['xss7q3z','mk2aa','mk3bb'])`), um zu sehen, welche Source überhaupt gelesen wird.
4. Wird die Source gar nicht gelesen? → Die Route/Aktion erreicht den Code nicht. Zurück zur Routen-Analyse (Hunt-Prompt Phase 1).

## 4. Log überläuft / Seite wird träge

1. `__xssClear()` zwischen Aktionen.
2. Auswertung nur mit `__xssDump(true)` (tainted only).
3. Bei dauerhaft trägen Seiten: Hooks punktuell einsetzen — erst Source triggern, Netzwerk beobachten, dann gezielt nur die verdächtige Komponente mit Hooks neu laden.
4. fetch/XHR-Hooks erzeugen auf API-lastigen SPAs viel Volumen → ggf. in der Datei Abschnitt 7 auskommentieren und neu injizieren.

## 5. Cross-Origin-iframe auf der Seite

- Konsole: Kontext-Dropdown (oben) auf den Frame stellen → dort injizieren. Jedes Frame-Log separat auswerten.
- Cross-Origin-Frames lesen ihren Inhalt nicht zulassen — das ist normal. Relevant ist nur, was zwischen den Frames per postMessage läuft (`postmessage-watch.js` in beiden Kontexten).

## 6. Jede Navigation killt die Hooks

1. Beste Lösung: CDP `Page.addScriptToEvaluateOnNewDocument` mit dem Hook-Quelltext — läuft dann vor jedem Dokument. Ob das verwendete DevTools-Tool das anbietet, prüfen.
2. Ohne CDP: Re-Injection-Routine — nach jeder harten Navigation zuerst injizieren, dann erst interagieren. Disziplin, kein Workaround.
3. Logs gehen bei Navigation verloren → vor jeder Navigation `__xssDump()` sichern (Artefakt-Disziplin des Hunt-Prompts).

## 7. Site hat Debugger-/Tamper-Erkennung

1. Minimal-Instrumentierung: nur die benötigten Hooks aus der Datei kopieren statt alles.
2. `console.warn`-Ausgaben im Hook stören manche Erkennungen → im Snippet entfernen.
3. Erkennung dokumentieren (sie ist selbst ein Schutzmechanismus-Befund), nicht bekämpfen.

## 8. Grundregel bei Unsicherheit

Wenn unklar ist, warum ein Hook nicht feuert: nicht raten. Die Ursache per Checkliste oben eingrenzen und das Ergebnis ins Phasen-Log schreiben — auch "Hook feuerte nicht, Grund: App cacht native Referenzen" ist ein verwertbares Ergebnis.
