# Kandidaten-Matrix — Arc (HackerOne `arc-bbp`)

- Target: `Arc via HackerOne` — https://hackerone.com/arc-bbp
- Researcher: `denibkv`
- Hunt-Datum: `2026-09-28` (Recon begonnen)
- Hunt-Prompt: `/home/user/Bugbounty/XSS-Agent-Wolt-v3.md`, Sektion 7 (Matrix) und Sektion 9 (Artefakte)
- Ablage der Belege: `/home/user/Bugbounty/evidence/arc/` — Regelwerk: `/home/user/Bugbounty/evidence/README.md`

Diese Datei wird **fortlaufend** geführt, nicht erst am Ende. Jede Zeile braucht einen Beleg:
Datei:Zeile, Request/Response-Paar oder Screenshot. Ohne Beleg keine Zeile.

Diese Datei wird versioniert (siehe `.gitignore`). Deshalb gehören hier **keine** Cookies, Tokens,
Zugangsdaten oder PII hinein — nur Pfade auf die Artefakte, die sie belegen.

---

## Scope (Stand 2026-09-28, Quelle: öffentlicher bounty-targets-Datensatz, Alter < 1 h)

| Asset | Bucket | Bounty | Max. Severity | Programm-Notiz |
| --- | --- | --- | --- | --- |
| `*.arc.io` | in scope | ja | critical | Tier-B-Auszahlung. **Nur Circle-eigene Assets.** |
| `rpc.testnet.arc.network` | in scope | ja | critical | — |
| `rpc.drpc.testnet.arc.network` | in scope | ja | critical | — |
| `github.com/circlefin/arc-node` | in scope (Source) | ja | critical | — |
| `github.com/circlefin/arc-remote-signer` | in scope (Source) | ja | critical | — |
| `github.com/circlefin/malachite` | in scope (Source) | ja | critical | Nur `code/crates` ohne `starknet` und `test`; alles außerhalb `code/crates` out of scope |
| `community.arc.io` | **out of scope** | — | — | — |
| `explorer.arc.io` | **out of scope** | — | — | — |
| `help.arc.io` | **out of scope** | — | — | — |

`arc.network` ist **kein** Wildcard — nur die zwei genannten RPC-Hosts sind gelistet. Deshalb
kein DNS-Bruteforce auf `arc.network` gelaufen.

---

## Asset-Inventar (Phase 1, belegt in `recon/phase1_note_20260928-1050.txt`)

Quelle: **nur** DNS-Bruteforce über `getaddrinfo` (`recon/resolve.py`, 3473 Anfragen).
CT-Logs und CDX-Archiv sind in dieser Umgebung per Egress-Policy blockiert — die Liste ist
eine **Untergrenze, keine Inventur**. Wildcard-Check vorab: 5 Zufallsnamen → alle NXDOMAIN,
also kein DNS-Wildcard, Treffer sind belastbar.

| Host | A / AAAA | Frontend | Scope | HTTP geprüft? |
| --- | --- | --- | --- | --- |
| `arc.io` | 198.202.211.1 | — (nicht Cloudflare) | in scope? → **Q6** | nein (Egress 403) |
| `www.arc.io` | 198.202.211.1, 2620:cb:2000::1 | — (nicht Cloudflare) | in scope | nein (Egress 403) |
| `docs.arc.io` | 162.159.143.13, 172.66.3.9 | Cloudflare | in scope | nein (Egress 403) |
| `portal.arc.io` | 104.18.20.97, 104.18.21.97 | Cloudflare | in scope | nein (Egress 403) |
| `portal-staging.arc.io` | 104.18.20.97, 104.18.21.97 | Cloudflare | in scope | nein (Egress 403) |
| `staging.arc.io` | 104.18.20.97, 104.18.21.97 | Cloudflare | in scope | nein (Egress 403) |
| `origin.arc.io` | 104.18.20.97, 104.18.21.97 | Cloudflare | in scope | nein (Egress 403) |
| `status.arc.io` | 13.226.251.79/85/107/120 | AWS CloudFront | in scope | nein (Egress 403) |
| `community.arc.io` | 104.18.6.42, 104.18.7.42 | Cloudflare | **out of scope** | nicht geprobt |
| `explorer.arc.io` | 104.26.0.65, 104.26.1.65, 172.67.72.116 | Cloudflare | **out of scope** | nicht geprobt |
| `help.arc.io` | 148.139.160.220 | — | **out of scope** | nicht geprobt |

Rohdaten: `recon/resolved-all.tsv`. Listen: `recon/hosts-inscope.txt`, `recon/out-of-scope.txt`.

---

## Matrix

Noch leer: ein XSS-Kandidat braucht Datei:Zeile, Source und Sink. Alle drei kommen aus
Stufe 5/6 (JS-Bundles, Source-Maps), die mangels Egress nicht gelaufen ist.

| # | Datei:Zeile | Funktion | Source | Sink | Route | Auth | Validierung | Payload | Ergebnis | Opfer-Link | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K01 |  |  |  |  |  |  |  |  |  |  |  |
| K02 |  |  |  |  |  |  |  |  |  |  |  |
| K03 |  |  |  |  |  |  |  |  |  |  |  |

Kandidaten-ID = Spalte `#` (`K01`, `K02`, …). Dieselbe ID ist der `{kandidat-id}`-Teil im
Dateinamen jedes zugehörigen Artefakts (`README.md`, Abschnitt Benennung).

### Status-Legende

Drei Zustände, kein vierter:

| Status | Bedeutung | Pflichtangabe |
| --- | --- | --- |
| `bestätigt` | Alert wurde in der Target-Origin beobachtet, Phase 9 vollständig abgehakt | Screenshot-Dateiname + Opfer-Link |
| `offen` | Kandidat lebt, Nachweis fehlt noch | Blocker-Notiz mit konkretem nächstem Schritt |
| `geschlossen (Grund)` | Kandidat ist erledigt | Grund aus der Taxonomie + Beleg |

Grund-Taxonomie beim Schließen: Sanitizer wirksam · CSP blockiert · Source nicht
angreiferkontrolliert · Route unerreichbar · Nur Self-XSS · Framework-Encoding greift ·
Duplikat (bekanntes Issue) · Out of Scope

"Wahrscheinlich verwundbar", "sollte triggern", "vermutlich gefiltert" sind keine Status.

### Blocker-Notizen (Pflicht bei jedem `offen`)

| Kandidat | Blocker exakt (was wurde entfernt/kodiert/ersetzt/geblockt) | bereits abgearbeitete Technik-Klassen | nächster konkreter Schritt |
| --- | --- | --- | --- |
|  |  |  |  |

---

## Versuchs-Log

**min. 5 Versuche / 3 Technik-Klassen, max. 8 Payload-Varianten pro Kandidat.**

| Kandidat | Versuch # | Technik-Klasse | Payload | Response-Diagnose |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

| Kandidat | Versuche | verschiedene Technik-Klassen | Mindestmaß erfüllt |
| --- | --- | --- | --- |
|  |  |  |  |

---

## Phasen-Log

| Phase | Datum | geprüft | gefunden | offen |
| --- | --- | --- | --- | --- |
| 0 — Scope-Verifikation & Duplikat-Check | 2026-09-28 | `recon/phase1_note_20260928-1050.txt` (Datensatz-Scope) | 6 In-Scope-, 3 Out-of-Scope-Assets | Q1–Q7, Programmseite nicht abrufbar |
| 1 — Asset-Inventar | 2026-09-28 | `recon/phase1_note_20260928-1050.txt`, `recon/resolved-all.tsv` | 8 In-Scope-Hosts unter `*.arc.io` (nur DNS) | CT-Logs + CDX blockiert → Liste unvollständig |
| 2 — CSP & Schutzschicht | — | — | — | **blockiert:** kein HTTP-Egress zum Target |
| 3 — Framework- & Sanitizer-Fingerprint | — | — | — | blockiert (setzt Phase 2 voraus) |
| 4 — Sink-Inventar | — | — | — | blockiert (keine Bundles) |
| 5 — Source-Inventar | — | — | — | blockiert (keine Bundles) |
| 6 — Reflection-Discovery & Upload-Vektoren | — | — | — | blockiert |
| 7 — Taint-Tracing | — | — | — | blockiert |
| 8 — Exploit-Bau | — | — | — | blockiert |
| 9 — Opfer-Verifikation | — | — | — | blockiert |
| 10 — Übergabe | — | — | — | blockiert |

Kein HAR für Phase 1 — es gab keinen HTTP-Verkehr zum Target, der einen hätte erzeugen können.
Beleg ist stattdessen die TSV-Rohausgabe des Resolvers.

---

## Offene Fragen an die Programmseite

| Frage | Quelle geprüft am | Antwort gefunden? | Konsequenz für den Hunt |
| --- | --- | --- | --- |
| In-Scope-Assets und Wildcards | 2026-09-28, bounty-targets-Datensatz | ja | `*.arc.io` + 2 RPC-Hosts + 3 Repos |
| Out-of-Scope-Liste | 2026-09-28, bounty-targets-Datensatz | ja | community/explorer/help.arc.io ausgeschlossen |
| **Q1** Automatisierung / Scanner / Rate Limits erlaubt? | — | **nein** | Stufe 7 (Fuzzing) entfällt, Stufe 2 sequenziell mit Delay |
| **Q2** Geforderter Identifikations-Header | — | **nein** | Default `User-Agent: denibkv-hackerone-research` als **Annahme** benutzt |
| **Q3** Regeln für eigene Testaccounts (mind. 2 nötig, Phase 9) | — | **nein** | Phase 9 nicht planbar |
| **Q4** Erstattungsfähigkeit von XSS-Varianten + was zahlt „Tier B"? | — | **nein** | Severity-Grundlage unbekannt |
| **Q5** Bekannte / bereits gemeldete Issues | — | **nein** | Duplikat-Risiko nicht abschätzbar |
| **Q6** Deckt `*.arc.io` die Apex `arc.io` mit ab? | — | **nein** | Apex ist kein eigenes Asset; Konvention sagt ja, Policy schweigt |
| **Q7** Welche Hosts sind „Circle-owned"? | — | **nein** | Wildcard ist darauf eingeschränkt; aus DNS nicht entscheidbar |

Quelle für Q1–Q7 ist https://hackerone.com/arc-bbp. Der Host ist aus dieser Umgebung per
Egress-Policy nicht erreichbar (403 auf CONNECT) — die Fragen bleiben bis zum manuellen
Nachlesen offen.
