# Live Nation — Live-Analyse (unauthentifiziert)

Stand 2026-09-28, nach Freigabe des Netzzugangs. Ersetzt die Netz-Einschränkung
aus `offline-analysis.md`; die dortigen Ergebnisse zu den npm-Paketen bleiben
gültig, eine ihrer Folgerungen wird unten **korrigiert**.

**Ergebnis: kein feuerbares XSS gefunden.** Was stattdessen belegt ist, steht
hier — inklusive der Flächen, die jetzt mit Beleg ausgeschlossen sind.

## 1 — Erreichbarkeit: Ticketmaster ist von hier nicht testbar

| Hostgruppe | Endstatus | Befund |
|---|---|---|
| `www.ticketmaster.*` (6 Hosts, via Apex-Redirect) | 403 | Body ist exakt `{"response":"block"}`, Server `Varnish`. Bot-Schutz gegen die Datacenter-IP. |
| `app.ticketmaster.*` (7), `app.livenation.com` | 404 auf `/` | Antworten, aber die Wurzel ist kein Dokument. API-/App-Origins, brauchen konkrete Pfade. |
| `signup.ticketmaster.com` | 403 | dito blockiert. Ausgerechnet das Kampagnen-Target. |
| `livenation.com`, `livenation.me`, `www.livenation.co.uk` | 200 | offen |
| `www.royalarena.dk`, `www.onthewaterfrontfestival.com` | 200 | offen |
| `www.lineup.com.mx`, `frontgatetickets.com` | 200 | offen |

Die 14 Ticketmaster-Hosts — also die Hälfte des Scopes und die vom Programm
ausdrücklich als interessant benannte Hälfte — sind aus diesem Container nicht
prüfbar. Das ist keine Aussage über ihre Sicherheit, sondern über die Herkunft
der Requests. Sie brauchen einen Wohn-IP-Pfad oder eine echte Browser-Session.

## 2 — Der Befund mit dem größten Gewicht: CSP mitigiert hier nichts

`www.livenation.co.uk` und `livenation.me` liefern eine ausführliche CSP — und
`script-src` enthält:

```
script-src 'self' … 'unsafe-inline' 'unsafe-eval' … (≈120 weitere Hosts)
```

`www.livenation.com` liefert **überhaupt keine** CSP.

Damit ist die CSP auf diesen Origins gegen XSS wirkungslos: `unsafe-inline`
erlaubt Inline-Handler und `javascript:`-URIs, `unsafe-eval` erlaubt
`eval`/`Function`. Für die Bewertung jedes künftigen Sink-Fundes auf diesen
Hosts heißt das: er feuert, es gibt keine zweite Verteidigungslinie. Beide Hosts
setzen zudem `SID` und `BID` als Cookies, der Origin trägt also Sitzungszustand.

Gegenprobe zur Framing-Fläche: alle `app.*`-Hosts setzen `frame-ancestors 'none'`
**und** `X-Frame-Options: DENY`. Frame-basierte `postMessage`-Angriffe gegen die
App-Origins sind damit aus; nur ein Popup käme noch in Frage.

## 3 — Plattform-Kartierung: vier In-Scope-Hosts, eine Codebasis

`www.livenation.co.uk`, `livenation.me`, `www.royalarena.dk` und
`www.onthewaterfrontfestival.com` laden **dieselben 50 JS-Chunks unter
identischen Pfaden** (`/_next/static/chunks/…?dpl=v135`), Pfad-Overlap 50/50 in
allen drei Vergleichen. Next.js App Router (`webpackChunk_N_E`, kein
`__NEXT_DATA__`), MUI, Emotion. Keine Source-Maps in Produktion.

Das CMS ist **Umbraco** — belegt über die Zod-Validatoren, die die App per
`new Function` kompiliert und die Feldnamen wie `umbracoFile` tragen.

Praktische Folge: ein Sink in dieser Codebasis ist ein Sink auf vier
In-Scope-Hosts gleichzeitig.

## 4 — Bestätigter Sink ohne Quelle

Im App-Bundle existiert eine generische Raw-HTML-Komponente (Modul `30935`):

```js
let s = ({ html: e, component: t = "div", variant: r, className: s, ...l }) =>
  "string" == typeof e
    ? jsx(Typography, { …l, dangerouslySetInnerHTML: { __html: e } })
    : jsx(Typography, { …l, children: e })
```

Wer `html="…"` übergibt, bekommt ungefilterte HTML-Injektion. Und:

- **Kein Sanitizer im gesamten App-Bundle.** `DOMPurify`, `dompurify`,
  `sanitize-html`, `xss`, `escapeHtml`: null Treffer. Das einzige `sanitize`
  liegt in Emotion-Interna, das einzige `htmlEscape` in Next.js-Interna.
- Importiert wird das Modul in `2310`, `4493`, `4980`, `6379` und
  `not-found`, jeweils für Alert-/Notification-Beschreibungen und
  Ticket-Beschreibungen (`html: t.description` in `4980` bei Zeile 7411 und 7475
  der beautifyten Datei).

Alle beobachteten Quellen sind Umbraco-/API-Felder, keine URL-Werte. Der Sink
ist damit belegt, die Quelle fehlt. Das ist der beste offene Lead: eine
angreiferbeeinflussbare Quelle in eines dieser Felder, und die fehlende CSP aus
Abschnitt 2 macht daraus sofort Script-Ausführung.

## 5 — Mit Beleg ausgeschlossen

Instrumentiert mit `dom-sink-hooker` (alle drei Snippets über
`addInitScript`, übersteht harte Navigation) in Chromium via Playwright.
Getestet: Homepage, 404, `/event`, `/festivalaccess`, `/account`, eine
Event-Detailseite, `frontgatetickets.com`, `www.lineup.com.mx`. Marker `DX_XSS`
in Pfad, Query (`redirect`, `q`, `keywords`, `message`, `error`, `alert`,
`notification`, `msg`, `title`, `name`) und Fragment.

**Kein URL-Wert erreicht einen HTML- oder Code-Sink.** Über alle Läufe waren die
einzigen tainted Treffer:

| Sink | Wert | Bewertung |
|---|---|---|
| `history.replaceState(url)` | die eigene URL | kein XSS-Sink |
| `JSON.parse` | RSC-Flight-Payload | escaped, s. u. |
| `a.href` | die eigene URL | von GTM/jQuery fürs Linktracking gesetzt |
| `xhr.open` | New-Relic-Telemetrie mit URL im Query | Drittanbieter-Beacon |

Einzelne Flächen:

- **Next.js-Escaping hält.** Der Query-Parameter landet im RSC-Flight-Payload
  innerhalb eines `<script>`. Zeichen-Probe mit `<svg/onload=1>"'\\`: im
  Response steht `aaPRBaa<svg/onload=1>`, Quotes
  backslash-escaped. `htmlEscapeJsonString` tut seine Arbeit; kein Ausbruch aus
  dem JSON-String.
- **404-Seite: 720 Sink-Aufrufe, 0 tainted.** Der Pfad fließt nirgendwohin.
- **Was die App wirklich in `innerHTML` schiebt**, sind React-/Next-Interna
  (`<script></script>`-Platzhalter), der GPT-Bootstrap und das
  Ketch-Consent-SDK (`cdn.ketchjs.com`, Drittanbieter, nicht im Scope). Kein
  App-Datenfeld.
- **`postMessage` ist eine Sackgasse.** Die registrierten Listener sind
  IAB-TCF- und GPP-Consent-Handler (`__tcfapiCall`, `__gppCall`). Sie prüfen
  `e.origin` nicht — das ist für die CMP-API spezifikationsgemäß — routen aber
  nur in `window.__tcfapi`/`__gpp` und antworten an `e.source`. Kein HTML- oder
  Code-Sink dahinter. Als Finding wäre das falsch.
  Hinweis fürs Nachvollziehen: der erste Listener in jedem Log ist der
  Hook selbst, nicht die Anwendung.
- **`frontgatetickets.com`** (Webflow + jQuery 3.5.1) hat einen echten
  Inline-Sink: `tempDiv.innerHTML = data` mit
  `data = await fetch("/events/" + slug).then(r => r.text())`. `slug` kommt aus
  `data-tracker-author-name` der eigenen Seite, `data` ist die eigene Seiten-HTML
  — erste Partei, nicht URL-kontrolliert. Die Suche daneben baut
  `` `${baseUrl}?*=${queryParams}` `` und weist das `location.href` zu; das
  Präfix ist hart `https://www.frontgatetickets.com/events`, ein Scheme-Wechsel
  ist damit ausgeschlossen.

## 6 — Korrektur zu `offline-analysis.md`

Die `href`-Hypothese aus der Offline-Runde gilt für diese Plattform **nicht**.
`@ticketmaster/aurora` ist auf den erreichbaren Live-Nation-Hosts nicht im
Einsatz: Fingerprints `getRelByTarget`, `LinkItemContainer`, `RowOptionsLink`,
`LinkCta` ergeben über alle 50 Chunks null Treffer. Die Live-Nation-Hosts fahren
MUI, nicht aurora.

Die Hypothese bleibt offen für `ticketmaster.com` und `app.ticketmaster.*` —
also genau die Hosts, die von hier nicht erreichbar sind. Sie ist nicht
widerlegt, nur am falschen Ort gesucht.

## 7 — Grenze dieses Durchlaufs

`/festivalaccess`, `/account` und die Event-Detailseite rendern aus diesem
Container „Internal Server Error" statt echtem Inhalt (Status 200 bzw. 404, aber
Fehlerseite im DOM). Der Sink aus Abschnitt 4 konnte deshalb nicht mit echten
CMS-Daten live beim Rendern beobachtet werden — nur statisch im Bundle belegt.
Auch das ist ein Herkunfts-Effekt, kein Anwendungszustand.

## 8 — Was als Nächstes trägt

1. **Ticketmaster von einem Wohn-IP-Pfad**, mit echtem Browser-Profil. 14 Hosts,
   die Hälfte des Scopes, vom Programm als Interessengebiet benannt, hier
   unberührt. Dort auch die aurora-`href`-Hypothese prüfen.
2. **Eine angreiferbeeinflussbare Quelle für den `html`-Prop-Sink** suchen: ein
   Umbraco-Feld oder API-Feld, das ohne Login schreibbar oder beeinflussbar ist.
   Newsletter-Anmeldung und Alert-Module sind die naheliegenden Kandidaten.
3. **Die CSP-Schwäche aus Abschnitt 2 separat einreichen**, falls das Programm
   Defense-in-Depth-Reports annimmt — `unsafe-inline` plus `unsafe-eval` auf
   einem sitzungstragenden Origin ist unabhängig von einem konkreten XSS eine
   Aussage wert. Vorher die Policy-Seite prüfen: viele Programme schließen
   CSP-Reports ohne Exploit aus.
