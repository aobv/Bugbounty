# Kandidaten-Matrix — Wolt (HackerOne)

- Target: `Wolt via HackerOne` — https://hackerone.com/wolt?type=team
- Researcher: `denibkv`
- Hunt-Datum: `____-__-__` (eintragen, bevor die erste Zeile entsteht)
- Hunt-Prompt: `/home/user/Bugbounty/XSS-Agent-Wolt-v3.md`, Sektion 7 (Matrix) und Sektion 9 (Artefakte)
- Ablage der Belege: `/home/user/Bugbounty/evidence/wolt/` — Regelwerk: `/home/user/Bugbounty/evidence/README.md`

Diese Datei wird **fortlaufend** geführt, nicht erst am Ende. Jede Zeile braucht einen Beleg:
Datei:Zeile, Request/Response-Paar oder Screenshot (Sektion 3). Ohne Beleg keine Zeile.

In dieser Datei steht **kein** vorab eingetragener Wolt-Fakt. Scope, Hosts, Routen, CSP und
Frameworks sind unbekannt, bis du sie beobachtet hast. Die einzige gefüllte Zeile unten ist als
BEISPIEL markiert und benutzt `beispiel.tld`.

Diese Datei wird versioniert (siehe `.gitignore`). Deshalb gehören hier **keine** Cookies, Tokens,
Zugangsdaten oder PII hinein — nur Pfade auf die Artefakte, die sie belegen.

---

## Matrix

| # | Datei:Zeile | Funktion | Source | Sink | Route | Auth | Validierung | Payload | Ergebnis | Opfer-Link | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `K00` — BEISPIELZEILE, Platzhalter, kein Finding, vor dem Hunt löschen | `app.min.js` → entminifiziert `src/lib/render.ts:87` | `renderBanner()` | `location.hash` | `element.innerHTML` | `/beispiel/pfad?x=1` | anonym | keine erkennbar | `"><img src=x onerror=alert('DX_XSS@'+location.origin)>` | Alert in Target-Origin beobachtet, Beleg `K00_screenshot_20260101-1200.png` | `https://beispiel.tld/beispiel/pfad#...` | BEISPIELZEILE (kein Status) |
| K01 |  |  |  |  |  |  |  |  |  |  |  |
| K02 |  |  |  |  |  |  |  |  |  |  |  |
| K03 |  |  |  |  |  |  |  |  |  |  |  |

Kandidaten-ID = Spalte `#` (`K01`, `K02`, …). Dieselbe ID ist der `{kandidat-id}`-Teil im
Dateinamen jedes zugehörigen Artefakts (`README.md`, Abschnitt Benennung).

### Status-Legende

Drei Zustände, kein vierter (Sektion 3):

| Status | Bedeutung | Pflichtangabe |
| --- | --- | --- |
| `bestätigt` | Alert wurde in der Target-Origin beobachtet, Phase 9 vollständig abgehakt | Screenshot-Dateiname + Opfer-Link |
| `offen` | Kandidat lebt, Nachweis fehlt noch | Blocker-Notiz mit konkretem nächstem Schritt (unten) |
| `geschlossen (Grund)` | Kandidat ist erledigt | Grund aus der Taxonomie + Beleg |

Grund-Taxonomie beim Schließen: Sanitizer wirksam · CSP blockiert · Source nicht
angreiferkontrolliert · Route unerreichbar · Nur Self-XSS · Framework-Encoding greift ·
Duplikat (bekanntes Issue) · Out of Scope

"Wahrscheinlich verwundbar", "sollte triggern", "vermutlich gefiltert" sind keine Status.

### Blocker-Notizen (Pflicht bei jedem `offen`)

| Kandidat | Blocker exakt (was wurde entfernt/kodiert/ersetzt/geblockt) | bereits abgearbeitete Technik-Klassen | nächster konkreter Schritt |
| --- | --- | --- | --- |
|  |  |  |  |

Ein Kandidat ohne nächsten Schritt ist nicht offen, sondern liegengelassen. Solange hier ein
unversuchter Schritt steht, wird der Turn nicht beendet (Sektion 4).

---

## Versuchs-Log

Belegt das Mindestmaß aus Sektion 4 und Sektion 9: **min. 5 Versuche / 3 Technik-Klassen,
max. 8 Payload-Varianten pro Kandidat.** Ohne diese Zeilen ist "ausgeschöpft" eine Behauptung.

| Kandidat | Versuch # | Technik-Klasse | Payload | Response-Diagnose |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

Response-Diagnose in der Sprache von `/home/user/Bugbounty/.claude/skills/waf-sanitizer-playbook/references/bypass-map.md`:
entfernt · kodiert · ersetzt · geblockt (Status/Body notieren) · stille 200 · durchgelassen, keine
Ausführung · ausgeführt.

Technik-Klasse ist die Klasse aus der Bypass-Map, nicht "anderer Payload". Fünf Varianten
derselben Klasse sind ein Versuch, kein Fortschritt.

Zählstand pro Kandidat (fortschreiben):

| Kandidat | Versuche | verschiedene Technik-Klassen | Mindestmaß erfüllt |
| --- | --- | --- | --- |
|  |  |  |  |

---

## Phasen-Log

Pro Phase am Gate ausfüllen (Sektion 6). Leere Zeile = Phase nicht abgeschlossen.

| Phase | Datum | geprüft | gefunden | offen |
| --- | --- | --- | --- | --- |
| 0 — Scope-Verifikation & Duplikat-Check |  |  |  |  |
| 1 — Asset-Inventar |  |  |  |  |
| 2 — CSP & Schutzschicht |  |  |  |  |
| 3 — Framework- & Sanitizer-Fingerprint |  |  |  |  |
| 4 — Sink-Inventar |  |  |  |  |
| 5 — Source-Inventar |  |  |  |  |
| 6 — Reflection-Discovery & Upload-Vektoren |  |  |  |  |
| 7 — Taint-Tracing |  |  |  |  |
| 8 — Exploit-Bau |  |  |  |  |
| 9 — Opfer-Verifikation |  |  |  |  |
| 10 — Übergabe |  |  |  |  |

Pro Phase gehört ein HAR in die Ablage (`README.md`). Der Dateiname der Phase steht in der
Spalte "geprüft", damit das Log auf den Beleg zeigt und nicht auf eine Erinnerung.

---

## Offene Fragen an die Programmseite

Alles, was Phase 0 nicht beantworten konnte, steht hier — nicht geraten, nicht aus anderen
Programmen übertragen.

| Frage | Quelle geprüft am | Antwort gefunden? | Konsequenz für den Hunt |
| --- | --- | --- | --- |
| In-Scope-Assets und Wildcards |  |  |  |
| Out-of-Scope-Liste |  |  |  |
| Automatisierung / Scanner / Rate Limits erlaubt? |  |  |  |
| Geforderter Identifikations-Header |  |  |  |
| Regeln für eigene Testaccounts (mind. 2 nötig, Phase 9) |  |  |  |
| Erstattungsfähigkeit von XSS-Varianten (Self-XSS, Sandbox-Domains, hoher Interaktionsbedarf) |  |  |  |
| Bekannte / bereits gemeldete Issues |  |  |  |
