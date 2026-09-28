# Live Nation Entertainment — Target-Matrix

- Programm: https://hackerone.com/live_nation
- Scope aufgelöst: 2026-09-28 (bounty-targets-Datensatz, Alter < 1 h)
- Bounties: ja · Submissions: offen · Max. Severity: critical (alle Assets)

## Programm-Regeln, die die Arbeit begrenzen

Aus den Asset-Notizen des Datensatzes:

1. **„Only the listed domains, other regional websites are out of scope."**
   Es gibt **keine Wildcards** in diesem Scope. Subdomain-Enumeration produziert
   hier also keine legitimen Ziele — was nicht in `scope/domains.txt` steht, ist
   out of scope, auch wenn es `*.ticketmaster.*` ist.
2. **„No automated scanning on checkout/ payment flows."**
   Jede Automatisierung muss Checkout-/Payment-Pfade ausschließen. Der
   Recon-Runner in `recon/` setzt das als Deny-Regex um.
3. Interesse des Programms laut Notizen: **Authentication** (`app.livenation.com`)
   und **API + Authentication** (alle `app.ticketmaster.*`).

Der Datensatz führt **Regeln nicht** — nur Assets. Reward-Tabelle, erlaubte
Testarten, Rate-Limits, Safe Harbour und die Frage, ob Self-XSS bzw. XSS hinter
Login akzeptiert wird, stehen ausschließlich auf der Policy-Seite oben. Vor dem
ersten aktiven Request dort nachlesen.

## Hosts (22, alle fix — keine Wildcards)

| Host | Rolle (Hypothese) | Programm-Notiz | Status |
|---|---|---|---|
| `app.livenation.com` | App-Origin, Session | Interesse: Authentication | 404 auf /, frame-ancestors none + XFO DENY |
| `app.ticketmaster.com` | App-Origin, Session | Interesse: API + Authentication | 404 auf /, nicht framebar |
| `app.ticketmaster.ca` | App-Origin regional | API + Authentication | 404 auf /, nicht framebar |
| `app.ticketmaster.co.uk` | App-Origin regional | API + Authentication | 404 auf /, nicht framebar |
| `app.ticketmaster.com.au` | App-Origin regional | API + Authentication | 404 auf /, nicht framebar |
| `app.ticketmaster.com.mx` | App-Origin regional | API + Authentication | 404 auf /, nicht framebar |
| `app.ticketmaster.eu` | App-Origin regional | API + Authentication | 404 auf /, nicht framebar |
| `app.ticketmaster.ie` | App-Origin regional | API + Authentication | 404 auf /, nicht framebar |
| `ticketmaster.com` | Consumer-Hauptorigin | — | **403 Bot-Block** von dieser IP |
| `ticketmaster.ca` | Consumer regional | — | **403 Bot-Block** |
| `ticketmaster.co.uk` | Consumer regional | — | **403 Bot-Block** |
| `ticketmaster.com.br` | Consumer regional | — | **403 Bot-Block** |
| `ticketmaster.com.mx` | Consumer regional | — | **403 Bot-Block** |
| `ticketmaster.de` | Consumer regional | — | **403 Bot-Block** |
| `livenation.com` | Consumer-Hauptorigin | — | 200, **keine CSP** |
| `livenation.me` | Consumer | — | 200, CSP mit unsafe-inline+eval, SID/BID |
| `www.livenation.co.uk` | Consumer regional | — | 200, unsafe-inline+eval, SID/BID, instrumentiert |
| `signup.ticketmaster.com` | **Kampagnen-Target**: Persona & ASU Sign-Up Verification | eigener Bounty-Campaign-Text am Asset | **403 Bot-Block** |
| `frontgatetickets.com` | Festival-Ticketing | — | 200, Webflow+jQuery, instrumentiert |
| `www.lineup.com.mx` | Regional-Ticketing | — | 200, Next.js, instrumentiert |
| `www.onthewaterfrontfestival.com` | Event-Site | — | 200, Codebasis wie co.uk |
| `www.royalarena.dk` | Venue-Site | — | 200, Codebasis wie co.uk |

Mobile (nicht Gegenstand dieser Web-XSS-Runde): `dk.royalarena.app`,
Apple-Store-IDs `1181913144`, `500003565`.

## Priorisierung für unauthentifiziertes DOM-XSS

Nach Origin-Wert, nicht nach Bequemlichkeit:

1. **`app.ticketmaster.com` / `app.livenation.com`** — Session-tragende
   App-Origins, vom Programm ausdrücklich als Interessengebiet benannt. Höchstes
   Ceiling: XSS hier trifft eine authentifizierte Session.
2. **`signup.ticketmaster.com`** — eigener Kampagnen-Scope rund um
   Sign-Up-Verification, also ein Flow der unauthentifiziert erreichbar sein
   *muss*. Genau die Kombination, die diese Aufgabe verlangt.
3. **`ticketmaster.com` / `livenation.com`** — Consumer-Origins, teilen
   Cookie-Domain mit den App-Origins. XSS hier ist über die Cookie-Domain
   relevant, auch ohne eigene Session.
4. **Venue-/Event-Sites** (`royalarena.dk`, `onthewaterfrontfestival.com`,
   `lineup.com.mx`) — kleinere, oft CMS-getriebene Codebasen, erfahrungsgemäß
   schwächer gehärtet, aber niedrigeres Ceiling ohne Session. Als Zweitwelle.

## Testfortschritt

Live-Durchlauf am 2026-09-28 nach Freigabe des Netzzugangs — Ergebnisse,
ausgeschlossene Flächen und der offene Lead in `live-analysis.md`.
Kurzfassung: **kein feuerbares XSS gefunden**. Die 14 Ticketmaster-Hosts sind von
dieser IP durch Bot-Schutz nicht prüfbar. Auf den erreichbaren
Live-Nation-Hosts erreicht kein URL-Wert einen HTML- oder Code-Sink; belegt ist
ein ungefilterter `dangerouslySetInnerHTML`-Sink, dem die angreiferkontrollierte
Quelle fehlt.
