---
name: web2-recon
description: Vollständige Recon-Pipeline für Web-Targets im autorisierten Bug-Bounty-Scope. Baut aus einer Root-Domain die Angriffsfläche auf — Subdomains über CT-Logs und DNS-Bruteforce, Live-Hosts mit Status/Titel/Server/CSP, historische und parametrisierte URLs, JS-Assets samt Source-Map-Rekonstruktion, Endpunkte, SPA-Routen und Datei-Upload-Vektoren. Arbeitet zweigleisig: mit den Standard-Binaries (subfinder, httpx, katana, gau, ffuf, dnsx), falls installiert, sonst über einen verifizierten Fallback aus curl, python3, node/Playwright und jq. Verwenden in den Phasen Scope-Verifikation, Asset-Inventar, Schutzschicht-Erfassung, Reflection-Discovery und Upload-Vektoren, vor dem ersten aktiven Request gegen ein neues Target, bei jeder Frage "welche Hosts, URLs, Parameter und Bundles gibt es überhaupt", und immer dann, wenn ein Recon-Werkzeug fehlt oder eine Quelle ausfällt.
---

# web2-recon

Grundregel: Recon liefert Angriffsfläche, keine Findings. Jedes Asset wird mit seiner Quelle belegt (CT-Log, CDX, Bundle, Crawl) — ein Host ohne Quelle existiert nicht. Vor jedem aktiven Request steht die Scope-Prüfung, nicht danach.

## Pflicht-Workflow

1. **Scope-Grenzen fixieren.** Checkliste in `references/pipeline.md` Abschnitt 0 abarbeiten: In-/Out-of-Scope und Wildcards, Automatisierungs- und Rate-Limit-Regeln, geforderter Identifikations-Header, Testaccount-Regeln, erstattungsfähige Varianten, bereits gemeldete Issues. Jede Antwort, die auf der Programmseite **nicht** steht, wird als offene Frage notiert — nie geraten. Erst danach ein aktiver Request.
2. **Subdomains.** Mindestens zwei unabhängige Quellen (CT-Log + DNS-Bruteforce). Vor jedem Bruteforce Wildcard-Check, sonst ist das Ergebnis Müll. Wildcards aus dem Scope auflösen, bevor ein Host geprobt wird.
3. **Live-Hosts.** Pro Host erfassen: Status, effektives Redirect-Ziel, Titel, `Server`, CSP (Header **und** `<meta>`), `Set-Cookie`, CORS-Header, `X-Frame-Options`. Das ist die Datengrundlage der Schutzschicht-Phase.
4. **URLs und Historie.** Parametrisierte URLs sind die XSS-Kandidaten. Quellen: CDX-Archiv, Crawl, `robots.txt`, `sitemap.xml`, Pfade aus Bundles und Source-Maps.
5. **JS-Assets und Source Maps** → `references/js-und-sourcemaps.md`. Jedes Bundle sichern, `sourceMappingURL` prüfen, `.map` rekonstruieren, minifizierte Bundles vor der Sink-Analyse durch `prettier` schicken.
6. **Endpunkte, Routen, Upload-Vektoren.** Endpunkt- und Secret-Regex auf Bundles und rekonstruierte Quellen, Routen mit Parameter-Segmenten priorisieren. Upload-Flächen → `references/upload-vektoren.md`.
7. **Übergabe.** Ergebnisse nach `evidence/<target>/recon/` schreiben und an die XSS-Phasen weiterreichen (Tabelle unten). Recon endet mit einer Kandidatenliste, nicht mit einer Bewertung.

## Situation → Datei

| Situation | Datei |
|---|---|
| Pipeline planen, Stufe für Stufe, mit und ohne Binaries | `references/pipeline.md` |
| Kein Go-Binary installiert, nur curl/python3/node/jq | `references/ohne-tools.md` |
| Bundle gesichert, Endpunkte/Secrets/Routen extrahieren | `references/js-und-sourcemaps.md` |
| `sourceMappingURL` gefunden, Quellen rekonstruieren | `references/js-und-sourcemaps.md` Abschnitt 3 |
| Upload-Formular, SVG/HTML/Markdown-Annahme, Dateiname-Feld | `references/upload-vektoren.md` |
| Alles in einem Lauf, Werkzeug-Erkennung automatisch | `scripts/recon.sh <root-domain>` |

## Übergabe an die XSS-Phasen

| Recon-Ergebnis | Nächster Schritt |
|---|---|
| CSP aus Header und `<meta>`, Trusted-Types-Direktive | Schutzschicht-Phase: entscheidet, welche Payload-Klassen überhaupt Sinn ergeben |
| Bundles, rekonstruierte Quellen, Routen mit Parameter-Segmenten | `dom-sink-hooker` — Sink-Inventar, Source-Inventar, Taint-Tracing |
| Sanitizer-Bibliothek im Bundle erkannt | `waf-sanitizer-playbook/references/dompurify.md` |
| Reflektierter Marker, Blocker beobachtet | `waf-sanitizer-playbook/references/bypass-map.md` + `payload-ladders.md` |
| Zustandsändernder Endpunkt, der einen Stored-Sink füttert | optional `csrf-hunter` für die Chain — kein Pflichtschritt im XSS-Ablauf |

## Verbote

- Kein aktiver Request vor abgeschlossener Scope-Prüfung. Out-of-Scope-Hosts werden notiert, nicht geprobt.
- Kein Werkzeug als vorhanden annehmen. Vor jedem Aufruf `command -v` — fehlt es, den Fallback-Weg nehmen und das im Protokoll vermerken.
- Eine leere Antwort einer Quelle heißt "Quelle ausgefallen", nie "keine Assets". Ausfall protokollieren, zweite Quelle ziehen.
- Kein Secret-Treffer ist ein Finding: Kandidat, Gültigkeit und Impact im Rahmen der Programmregeln klären, niemals fremde Credentials benutzen.
- Rate-Limits gehören in den Aufruf, nicht in die Doku. Programmregeln zu Automatisierung haben Vorrang vor jeder Parallelität; im Zweifel sequenziell mit Delay.
- Ohne HTTP-Egress zum Target läuft nur die DNS-Stufe. Dann wird hier gebaut und dort gejagt, wo Egress existiert — kein Ergebnis aus einer blockierten Verbindung interpretieren.
