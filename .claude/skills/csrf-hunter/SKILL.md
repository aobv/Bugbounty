---
name: csrf-hunter
description: Systematisches Jagd- und Bypass-Werkzeug für CSRF auf autorisierten Bug-Bounty-Targets. Findet zustandsändernde Endpunkte, zerlegt deren Schutzmechanismen (CSRF-Token, SameSite, Origin/Referer-Prüfung, Custom-Header-Pflicht, CORS) und arbeitet pro Schutz eine Bypass-Leiter ab — Token-Weitwurf, SameSite=Lax-/None-Ausnutzung, Origin-Regex- und null-Origin-Bypasses, Content-Type-Downgrades, Method-Override, Login/Logout-CSRF, Cookie-Tossing. Verwenden bei jeder CSRF-Analyse auf autorisierten Targets, beim Aufbau der Endpunkt-Inventur, bei der Frage ob ein Request cross-site wiederholbar ist, bei blockierten CSRF-PoCs und für PoC-Erstellung mit Impact-Nachweis. Nur auf Targets anwenden, für die eine schriftliche Autorisierung (Bug-Bounty-Scope) vorliegt.
---

# csrf-hunter

Grundregel: CSRF ist eine Eigenschaft des Requests, nicht der Seite. Ein Finding existiert erst, wenn ein zustandsändernder Request cross-site tatsächlich wiederholt wurde (echter zweiter Browser-Kontext oder sauber simulierter Cross-Site-Kontext) und der Server ihn akzeptiert hat. Ein fehlender Token allein ist ein Verdacht, kein Finding.

Scope-Disziplin: Vor jedem Test prüfen, dass Host und Endpunkt im Bug-Bounty-Scope liegen und die Aktion harmlos ist (eigene Testaccounts, keine fremden Daten ändern, keine destruktiven Aktionen). Im Zweifel: eigenen Account als Opfer, eigenen Angreifer-Kontext.

## Pflicht-Workflow

1. **Inventur.** Alle zustandsändernden Requests sammeln (POST/PUT/PATCH/DELETE, plus GET mit Seiteneffekt). Echte Browser-Session surfen, History exportieren, dann `scripts/csrf_audit.py <export>` laufen lassen — es listet Kandidaten mit fehlendem Token, SameSite-Attributen der Cookies und Simple-Request-Eignung. Manuell ergänzen, was der Crawl nicht sieht (Multi-Step-Flows, WebSocket-Handshake → CSWSH-Verdacht).
2. **Schutz-Diagnose pro Kandidat.** Exakt festhalten, welche Schichten greifen: Token (Lage, Bindung, Validierung), SameSite der Session-Cookies, Origin/Referer-Prüfung, Custom-Header-Pflicht, CORS-Policy, Content-Type-Erzwingung. Tabelle pro Kandidat — ohne sie kein Bypass. Details in `references/schutz-analyse.md`.
3. **Bypass-Leiter abarbeiten.** Pro aktivem Schutz die Leiter in `references/bypass-leitern.md` von oben nach unten. Ein Versuch testet genau eine Annahme; Request und Server-Antwort (Status + Seiteneffekt ja/nein) notieren.
4. **PoC erst bei echtem Durchgriff.** Template aus `assets/` wählen (Form-Auto-Submit, credentialed fetch, JSON-via-text/plain), mit eigenem Opfer-Account im zweiten Browser-Profil ausführen, Seiteneffekt serverseitig verifizieren. Impact-Satz: was kann ein Angreifer beim Opfer auslösen, warum ist das schlimm (Aktion + Datenwert).
5. **Buchführung.** Jeder Versuch = Endpunkt + Schutzschicht + Variante + Ergebnis. Mindestmaß: pro ernstem Kandidaten 5 Versuche über 3 Schutzschichten, bevor er als "nicht verwundbar" gilt.
6. **Nach dem Hunt:** Gewinner-Muster und hartnäckige Schutz-Konfigurationen in `references/field-notes.md` eintragen.

## Situation → Datei

| Situation | Datei |
|---|---|
| Endpunkt-Inventur aus Browser-Traffic / Burp-Export | `scripts/csrf_audit.py` |
| Unklar, welche Schutzschicht aktiv ist | `references/schutz-analyse.md` |
| Schutzschicht bekannt, Bypass nötig | `references/bypass-leitern.md` |
| SameSite-Verhalten, Lax+POST-Fenster, Browser-Unterschiede | `references/samesite-matrix.md` |
| Login/Logout-CSRF, WebSocket (CSWSH), Cookie-Tossing, JSON-Endpoints | `references/spezialfaelle.md` |
| PoC bauen | `assets/poc-form.html`, `assets/poc-fetch.html`, `assets/poc-json.html` |
| Hunt beendet, Wissen sichern | `references/field-notes.md` |

## Verbote

- Kein Test außerhalb des autorisierten Scopes; keine Aktionen gegen fremde Accounts oder Produktivdaten.
- Kein Finding ohne serverseitig verifizierten Seiteneffekt aus cross-site Kontext. "Token fehlt" reicht nicht.
- Kein Aufgeben eines Kandidaten vor 5 Versuchen über 3 Schichten. Danach: offen mit Diagnose-Tabelle und nächstem Schritt, nie still geschlossen.
- Kein Mischen mehrerer Bypass-Annahmen in einem Versuch — sonst ist das Ergebnis nicht attribuierbar.
- Kein PoC, der nur theoretisch abschickt: jedes Template wird wirklich im zweiten Profil geladen und die Wirkung geprüft.
