# Artefakt-Disziplin — `evidence/`

Grundregel: **Ohne Artefakt keine Behauptung.** Sektion 3 des Hunt-Prompts
(`/home/user/Bugbounty/XSS-Agent-Wolt-v3.md`) ist nur erfüllbar, wenn jeder Beleg als Datei auf der
Platte liegt. Dieses Verzeichnis ist diese Platte. Sektion 9 des Prompts definiert die Regeln,
diese Datei macht sie benutzbar.

## 1 — Ablagestruktur

```
/home/user/Bugbounty/evidence/
├── README.md              (diese Datei, versioniert)
└── <target>/              hier: wolt/
    ├── wolt_matrix.md     Kandidaten-Matrix, Versuchs-Log, Phasen-Log (versioniert)
    ├── recon/             Rohausgabe der Recon-Phase: Subdomains, Hosts, URLs, JS, Source-Maps
    └── *.har *.txt *.png  Belege nach dem Benennungsschema unten (NICHT versioniert)
```

Ein Verzeichnis pro Target (`<target>` = `wolt`). Nichts liegt außerhalb. Kein Beleg im
Scratchpad, kein Beleg in `/tmp` — was dort liegt, ist nach der Session weg und belegt nichts.

## 2 — Benennung

```
{kandidat-id}_{typ}_{YYYYMMDD-HHmm}.{png,har,txt}
```

- `{kandidat-id}` — die ID aus Spalte `#` der Matrix (`K01`, `K02`, …). Phasen-Artefakte, die zu
  keinem Kandidaten gehören, bekommen `phase0` … `phase10` an dieser Stelle.
- `{typ}` — festes Vokabular, damit Dateien sortierbar bleiben:

| `{typ}` | Endung | Inhalt |
| --- | --- | --- |
| `har` | `.har` | Netzwerk-Mitschnitt einer Phase oder eines Kandidaten-Durchlaufs |
| `reqres` | `.txt` | rohes Request/Response-Paar, ein Kandidat, ein Versuch |
| `screenshot` | `.png` | Bildbeleg, bei Bestätigung mit sichtbarem Origin-Marker |
| `note` | `.txt` | Beobachtung, Blocker-Diagnose, Reproduktionsschritte |
| `payload` | `.txt` | finaler Payload plus Begründung, warum er in diesem Kontext trägt |
| `paket` | `.txt` | Übergabe-Paket nach Sektion 8, ein bestätigtes Finding |

- `{YYYYMMDD-HHmm}` — Zeitpunkt der Beobachtung, nicht der Ablage.

Beispiele (generisch, keine Wolt-Daten): `phase2_har_20260101-0930.har`,
`K01_reqres_20260101-1014.txt`, `K01_screenshot_20260101-1042.png`, `K01_paket_20260101-1100.txt`.

## 3 — Was wann abgelegt wird

| Auslöser | Pflicht-Artefakt |
| --- | --- |
| Phase abgeschlossen (Gate) | ein HAR der Phase, Dateiname ins Phasen-Log der Matrix |
| neuer Kandidat | das rohe Request/Response-Paar, das ihn begründet |
| jeder Payload-Versuch | Response-Diagnose als Zeile im Versuchs-Log, bei unklarem Verhalten zusätzlich `reqres` |
| Bestätigung | Screenshot mit sichtbarem Origin-Marker (`DX_XSS@<origin>`) |
| Kandidat geschlossen | der Beleg, der den Schließ-Grund trägt — kein Grund ohne Beleg |
| bestätigtes Finding | vollständiges Übergabe-Paket nach Sektion 8 als `paket`-Datei |

Der Dateiname gehört in dieselbe Matrix-Zeile. Ein Artefakt, auf das nichts zeigt, ist verloren;
eine Matrix-Zeile ohne Artefakt ist eine Behauptung.

## 4 — Scrubbing-Pflicht (vor dem Ablegen, nicht danach)

Beweismaterial entsteht mit Session-Daten darin. Ein Chromium-HAR enthält standardmäßig
vollständige Cookies und Auth-Header. Bereinigt wird **bevor** die Datei in `evidence/` landet.

Zu entfernen bzw. durch `[REDACTED]` zu ersetzen:

| Kategorie | Konkret |
| --- | --- |
| Header (Request) | `Cookie`, `Authorization` (inkl. Bearer-Wert), `Proxy-Authorization`, `X-API-Key`, `api-key`, `apikey`, `X-CSRF-Token`, `X-Auth-Token`, `X-Session-Id` |
| Header (Response) | `Set-Cookie` |
| HAR-Strukturen | `request.cookies`, `response.cookies` |
| URL-Parameter | `token`, `access_token`, `id_token`, `session`, `sid`, `auth`, `key`, `signature` |
| Body / Storage | JWTs (`eyJ…`), API-Keys, Passwörter, Refresh-Tokens, `localStorage`/`sessionStorage`-Dumps mit Auth-Material |
| PII | E-Mail-Adressen, Klarnamen, Telefonnummern, Postanschriften, Zahlungsdaten, Geokoordinaten, Device-/Kunden-IDs sowie alle Transaktions- und Bestelldaten, die das Target führt — eigene wie fremde |

Der eigene Testaccount ist kein Freibrief: auch dessen Session-Cookie gehört nicht in eine Datei,
die liegen bleibt.

HAR bereinigen (verifiziert gegen ein Probe-HAR; `jq` ist vorhanden):

```bash
jq '
["cookie","set-cookie","authorization","proxy-authorization","x-api-key","api-key","apikey","x-csrf-token","x-auth-token","x-session-id"] as $H
| def redact: map(.name as $n | if ($H | index($n | ascii_downcase)) then .value = "[REDACTED]" else . end);
  .log.entries |= map(
    .request.headers  |= redact
  | .response.headers |= redact
  | .request.cookies   = []
  | .response.cookies  = []
  | .request.url |= gsub("(?<p>[?&](?i)(token|access_token|id_token|session|sid|auth|key|signature)=)[^&]*"; "\(.p)[REDACTED]")
)' roh.har > K01_har_20260101-1014.har && rm roh.har
```

Grenze dieses Filters, ehrlich benannt: er fasst **Header, Cookie-Strukturen und URL-Parameter**
an, **nicht** Request- und Response-Bodies. Bodies werden von Hand durchgesehen — dort stecken
E-Mail-Adressen, Adressdaten und Tokens im JSON.

Kontrolle nach dem Bereinigen, vor dem Ablegen:

```bash
grep -rIEni 'set-cookie|authorization|bearer |eyJ[A-Za-z0-9_-]{8,}\.eyJ|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' \
  /home/user/Bugbounty/evidence/wolt/
```

Jeder Treffer wird geprüft, bevor die Datei bleibt. Kein Treffer ist keine Garantie — der Blick in
die Datei ersetzt kein grep, und grep ersetzt keinen Blick.

Screenshots: nur den Bereich aufnehmen, der den Beleg trägt (Alert-Dialog, Origin, URL-Leiste).
Sichtbare Kontodaten, Adressen, Transaktionshistorie oder fremde Namen vorher schwärzen oder den
Ausschnitt anders wählen. Ein frisches Profil mit einem eigenen Testkonto zeigt von sich aus
weniger — Phase 9 verlangt es ohnehin.

Die Matrix (`wolt_matrix.md`) wird versioniert. Dort stehen Pfade auf Artefakte, Payloads und
Diagnosen — keine Tokens, keine Cookies, keine PII.

## 5 — Weitergabe

- Findings werden nicht Dritten gezeigt, nicht gepostet, nicht in öffentliche Repos gelegt
  (Sektion 2 des Hunt-Prompts).
- `/home/user/Bugbounty/.gitignore` hält die Artefakte aus dem Repo heraus. Versioniert sind nur
  diese Datei, `*_matrix.md` und die `.gitkeep`-Dateien. Die Ignore-Regel ist eine zweite
  Sicherung, nicht die erste: die erste ist das Scrubbing aus Abschnitt 4.
- `git add -f` auf ein Artefakt ist der Weg, diese Sicherung zu umgehen. Wenn du ihn gehst, weißt
  du warum — und die Datei ist vorher bereinigt.
- Stored-Testobjekte im Target aufräumen (Sektion 2). Ein Artefakt ersetzt das Aufräumen nicht.
