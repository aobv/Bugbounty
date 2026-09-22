# DOMPurify: Versions- und Config-Analyse

## 1. Version und Config erfassen

- Version: `DOMPurify.version` in der Konsole; sonst im Bundle nach der Versionszeichenkette suchen.
- Config: alle Aufrufstellen von `DOMPurify.sanitize(...)`, `DOMPurify.setConfig(...)`, `DOMPurify.addHook(...)` finden und lesen. Keine Config gelesen = keine Aussage über DOMPurify.

## 2. Config-Matrix: Option → Risiko → Test

| Option | Risiko wenn gesetzt | Test |
|---|---|---|
| `ALLOWED_TAGS` enthält `svg`, `math` | Namespace-Verwirrung | mXSS-Leiter (`mxss.md`) |
| `ALLOWED_TAGS` enthält `form`, `style` | Form-Nesting / Style-Kontextwechsel | Vektor-Klassen 2 und 4 in `mxss.md` |
| `ADD_ATTR` mit `style`, `formaction`, `xlink:href` | Attribut-basierte Ausführung | `javascript:` in formaction/xlink:href |
| `SAFE_FOR_TEMPLATES` fehlt/false + Template-Framework vorhanden | `{{...}}` wird nach Sanitize kompiliert | Template-Marker senden |
| `RETURN_DOM: true` | Ausgabe ist DocumentFragment — wie wird es eingefügt? | Einfügestelle auf Roundtrip prüfen |
| `RETURN_TRUSTED_TYPE: true` | TT-Policy des Sanitizers prüfbar | Policy-Quelltext lesen |
| `USE_PROFILES` | genau definierte Erlaubmenge | Profil-Inhalt gegen Gefahren-Liste prüfen |
| `WHOLE_DOCUMENT: true` | komplettes Dokument inkl. head | base/meta/title-Vektoren zusätzlich |
| Custom-Hooks (`beforeSanitize*`/`afterSanitize*`) | häufigster Fehlerpunkt: selbstgebaute Hook-Logik | Hook-Quelltext Zeile für Zeile lesen; was der Hook entfernt/hinzufügt, kann er auch kaputt machen |

## 3. Testfolge (in dieser Reihenfolge)

1. **Config-Review** (Matrix oben).
2. **Namespace-Verwirrung:** SVG/MathML-Nesting inkl. `foreignObject`, `annotation-xml`, `desc`, `title`.
3. **mXSS-Roundtrip:** Wird die Sanitizer-Ausgabe per innerHTML eingefügt und später erneut gelesen/eingefügt? Harness: `assets/mxss-harness.js` — `__mxssStart()` gibt den Starter-Vektorsatz, `__mxssTest(...)` führt aus.
4. **Kommentar-/CDATA-Konstrukte** in fremden Namespaces.
5. **Template-Zusammenhang** (siehe Matrix SAFE_FOR_TEMPLATES).
6. **Hook-Implementierung** lesen.
7. **Doppelte Normalisierung:** Server sanitisiert zusätzlich? Reihenfolge klären (bypass-map.md).

## 4. Versionsbezogene Lücken

Keine fixe Payload-Liste — die veraltet. Vorgehen:

1. Gefundene Version exakt notieren.
2. Öffentliche Forschung zur Version suchen: "DOMPurify bypass <version>", Cure53-Advisories, mXSS-Forschung (Heiderich u. a.), Kinugawas DOMPurify-Writeups. Klassen der Vergangenheit: Namespace-Verwirrung über spezifische SVG/MathML-Elemente, Kommentar-basierte Kontextwechsel, mXSS über Roundtrips.
3. Jede gefundene Klasse lokal gegen die exakte Version verifizieren. Nie aus dem Gedächtnis behaupten — keine Belege, keine Aussage.

## 5. Abschluss-Regel

DOMPurify aktuell + restriktive Config + kein Roundtrip + Hooks sauber → Kandidat schließen ("Sanitizer wirksam") mit Version, Config und durchlaufener Testfolge als Begründung. Ein so geschlossener Kandidat ist ein verwertbares Ergebnis.
