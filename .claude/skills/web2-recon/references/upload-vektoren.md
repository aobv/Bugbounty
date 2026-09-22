# Datei-Upload als XSS-Vektor

Merksatz: **Die Origin entscheidet über den Impact, nicht der Payload.** Ein perfekt ausgeführtes SVG auf einer Sandbox- oder CDN-Origin ohne Session ist meist schwach bis unbelohnbar; dasselbe SVG auf der Anwendungs-Origin mit gültiger Session ist ein vollwertiges XSS. Deshalb stehen die Auslieferungs-Fragen vor der Payload-Arbeit, nicht danach.

## 1 — Vier Fragen vor jedem Upload-Versuch

Ohne belegte Antworten auf diese vier Fragen ist jeder Upload-Payload Blindflug:

| Frage | Warum sie entscheidet |
|---|---|
| **Auf welcher Origin** wird die Datei ausgeliefert? | Gleiche Origin wie die App → Session-Zugriff. Eigene Sandbox-/CDN-Origin → kein Session-Zugriff, Impact sinkt drastisch. Subdomain der App → hängt an Cookie-`Domain` und `SameSite`. |
| **Mit welchem `Content-Type`**? | `image/svg+xml` und `text/html` rendern. `application/octet-stream`, `text/plain` oder ein falsches `image/*` rendern nicht. Ohne `X-Content-Type-Options: nosniff` kann Sniffing das kippen. |
| **Mit welchem `Content-Disposition`**? | `attachment` erzwingt Download und tötet die Ausführung. `inline` (oder fehlender Header) lässt rendern. Ein `filename=` im Header ist zusätzlich ein Injection-Kandidat. |
| **Bleibt die URL rate- und ratbar?** | Zufälliger, nicht enumerierbarer Pfad plus Auth-Pflicht drückt den Impact; ein vorhersagbarer öffentlicher Pfad hebt ihn. |

Diese vier Werte werden am hochgeladenen Objekt **beobachtet** (Response-Header der Auslieferung lesen), nie aus dem Upload-Formular geschlossen.

## 2 — Vektoren

### SVG

Der ergiebigste Vektor, weil SVG legitimer Bild-Upload ist und trotzdem Skript trägt.

- Ausführung nur, wenn die Datei **direkt** aufgerufen wird und als `image/svg+xml` oder `text/html` ausgeliefert wird. Eingebettet über `<img src=…>` führt SVG **kein** Skript aus — der direkte Link ist der Beweis, nicht die Vorschau in der App.
- Konstrukte, die es zu testen lohnt: `<script>` im SVG-Namespace, `onload` am `<svg>`-Element, `<foreignObject>` mit HTML-Inhalt, `<animate>`/`<set>` mit `attributeName="href"`, externe Referenz über `xlink:href`.
- Sanitizer im Spiel (serverseitig oder clientseitig)? Dann ist das eine Sanitizer-Aufgabe: `waf-sanitizer-playbook/references/dompurify.md`, bei Roundtrip-Verdacht `references/mxss.md`.

### HTML / HTM / XHTML

- Direkter Treffer, wenn die Extension durchgeht und `text/html` ausgeliefert wird. Genau deshalb blocken die meisten Uploads sie — hier lohnt die Extension-Leiter aus Abschnitt 3.
- Nachbarformate mit HTML-Rendering prüfen: `.xhtml`, `.shtml`, `.xml` (mit Stylesheet-PI), `.mhtml`, `.swf`-Reste, PDF mit eingebettetem JS (eigener Impact-Pfad, nicht dieselbe Klasse).

### Markdown / Rich-Text / WYSIWYG

- Kein Datei-Upload im engeren Sinn, aber dieselbe Flanke: Markdown-Renderer erlauben oft rohes HTML oder lassen `javascript:`-URLs in Links durch.
- Zu testen: rohes HTML im Markdown, Link-URL mit `javascript:`, Bild-`onerror` über HTML-Passage, Referenz-Link-Definitionen, verschachtelte Code-Fences, die den Renderer aus dem Escaping werfen.
- Der Renderer läuft oft **client**seitig — dann ist es eine DOM-Sink-Frage: `dom-sink-hooker` instrumentieren und beobachten, welche Sink den gerenderten String bekommt.

### Metadaten: Dateiname und EXIF

Oft der einzige Teil des Uploads, der ungefiltert in eine Seite zurückfließt.

- **Dateiname**: wird er in der Datei-Liste, in einer Fehlermeldung, im `Content-Disposition` oder in einer E-Mail reflektiert? Marker in den Namen legen (`xss7q3z`), hochladen, jede Anzeigefläche prüfen — auch die Admin-Ansicht, wenn eine erreichbar ist.
- **EXIF/Metadaten** in JPEG/PNG (`Artist`, `Comment`, `Copyright`, `Description`): manche Anwendungen zeigen sie an. Marker setzen und nach Reflexion suchen.
- Beides ist reine Reflection-Arbeit: Marker rein, Anzeigefläche finden, Kontext bestimmen, dann die Leiter aus `waf-sanitizer-playbook/references/payload-ladders.md` für genau diesen Kontext.

## 3 — Bypass-Leiter für die Upload-Validierung

Von oben nach unten, ein Versuch testet eine Annahme. Jeder Versuch wird mit Request und beobachteter Auslieferung protokolliert.

| Stufe | Technik | Was sie prüft |
|---|---|---|
| 1 | `Content-Type` im Multipart-Part fälschen (`image/png` bei SVG-Inhalt) | prüft der Server nur den Client-Wert? |
| 2 | Magic Bytes voranstellen (`GIF89a;` vor SVG/HTML-Inhalt) | prüft er nur die ersten Bytes, nicht den Rest? |
| 3 | Doppel-Extension (`x.png.svg`, `x.svg.png`) | welchen Teil nimmt die Validierung, welchen die Auslieferung? |
| 4 | Case und Whitespace (`.SVG`, `.sVg`, `.svg `, `.svg%00.png`) | naive String-Vergleiche und Trailing-Handling |
| 5 | Alternative Extension mit gleichem Rendering (`.xhtml`, `.shtml`, `.xml`) | Blocklist statt Allowlist? |
| 6 | Filename-Injection: Pfadanteile, `"`/`;`/CR-LF im Namen | Header-Injection in `Content-Disposition`, Pfad-Kontrolle |
| 7 | Content-Type-Parameter anhängen (`image/svg+xml; charset=utf-8`, `text/html;x=.png`) | Parser-Unterschiede zwischen Validierung und Auslieferung |

Mindestmaß wie überall: 5 Versuche über 3 Technik-Klassen, bevor eine Upload-Fläche als "nicht verwundbar" geschlossen wird. Danach offen mit Blocker-Notiz, nie still geschlossen.

## 4 — Disziplin

- **Nichts hochladen, was nicht entfernt werden kann.** Stored-Vektoren werden nach dem Beleg aufgeräumt; was nicht löschbar ist, kommt vorher nicht hoch.
- **Keine fremden Nutzer als Testfläche.** Eigene Testaccounts, eigene Sichtbarkeit; öffentlich sichtbare Uploads nur, wenn die Programmregeln das decken.
- **Payload minimal halten.** Marker statt Nutzlast; der Beweis ist die Ausführung in der richtigen Origin, nicht der Umfang des Skripts.
- **Ein Upload, der irgendwo als Datei liegt, ist kein Finding.** Erst die beobachtete Ausführung im Opferkontext auf der relevanten Origin zählt.
