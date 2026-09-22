---
name: waf-sanitizer-playbook
description: Vollständiges Bypass-Entscheidungswerkzeug für blockierte XSS-Payloads. Übersetzt jeden exakt dokumentierten Blocker (welches Zeichen, Keyword oder Tag gefiltert, kodiert oder ersetzt wurde) in die nächste zu testende Bypass-Technik-Klasse, mit kompletten Payload-Leitern pro Injektionskontext (HTML-Body, Attribut, JS-String, URL, CSS, Kommentar, JSON-Blob, SVG/MathML), DOMPurify-Analyse, mXSS-Testbibliothek und WAF-Notizen. Verwenden bei jedem blockierten Payload, beim Erfüllen des Persistenz-Mindestmaßes (5 Versuche / 3 Technik-Klassen), bei Sanitizer- und Mutation-XSS-Tests und nach jedem Hunt zum Einpflegen Gelerntes.
---

# waf-sanitizer-playbook

Grundregel: Ein Blocker ist eine Diagnose-Aufgabe, kein Endpunkt. Du darfst einen Kandidaten erst dann aufgeben, wenn die Leiter für seinen Kontext ausgeschöpft ist — belegt, Klasse für Klasse.

## Pflicht-Workflow

1. **Diagnose vor Aktion.** Was wurde gesendet, was kommt in der Response an? Pro Zeichen festhalten: entfernt / kodiert (wie?) / ersetzt (wodurch?) / Request komplett geblockt (WAF?). Ohne diese Tabelle kein Bypass-Versuch.
2. **Kontext bestimmen** (HTML-Body, Attribut quoted/unquoted, JS-String, URL, CSS, Kommentar, JSON-Blob, SVG/MathML) → die Leiter für diesen Kontext aus `references/payload-ladders.md` von oben nach unten abarbeiten.
3. **Bei Block:** Blocker in `references/bypass-map.md` nachschlagen → nächste Klasse. Nicht klassenübergreifend mischen — ein Payload testet eine Klasse.
4. **Sanitizer im Spiel** → `references/dompurify.md`. **Roundtrip-Verdacht** → `references/mxss.md` + `assets/mxss-harness.js`. **WAF** → `references/waf-notes.md`.
5. **Buchführung:** Jeder Versuch = Klasse + Payload + Response-Unterschied, fortlaufend notiert. Mindestmaß: 5 Versuche über 3 Klassen pro Kandidat.
6. **Nach dem Hunt:** Gewinner in `references/field-notes.md` eintragen, wiederkehrende Muster in `bypass-map.md` hochziehen.

## Situation → Datei

| Situation | Datei |
|---|---|
| Payload blockiert, Blocker bekannt | `references/bypass-map.md` |
| Kontext klar, aber keine Payload-Idee | `references/payload-ladders.md` |
| DOMPurify identifiziert | `references/dompurify.md` |
| innerHTML-Roundtrip / Sanitizer-Ausgabe wird erneut geparst | `references/mxss.md` + `assets/mxss-harness.js` |
| WAF-Blockseite / 403 / 406 | `references/waf-notes.md` |
| Hunt beendet, Wissen sichern | `references/field-notes.md` |

## Verbote

- Kein "sollte funktionieren" — jede Variante wird gesendet und die Response gelesen.
- Keine Klassen-Mischung in einem Payload.
- Kein Aufgeben vor 5 Versuchen / 3 Klassen. Danach: offen mit Blocker-Notiz und nächstem Schritt, nie still geschlossen.
