# Schutz-Diagnose pro Kandidat

Pro Kandidat eine Tabelle mit diesen Schichten füllen. Jede Schicht: **aktiv / nicht aktiv / unbekannt** + Beleg (beobachtetes Verhalten, nicht Vermutung).

## 1. CSRF-Token

Fragen, der Reihe nach:

- Existiert ein Token? Wo: Body-Parameter, Custom-Header (`X-CSRF-Token`, `X-XSRF-TOKEN`), doppelter Cookie (`Cookie: session=…; csrf=…` + Header/Body-Echo)?
- Wird er serverseitig validiert? Test: Request mit **entferntem** Token senden. Dann mit **leerem**, dann **verändertem** (1 Zeichen), dann **Token aus anderer Session** (zweiter Account), dann **Token von anderem Endpunkt**.
- Bindung: Gilt der Token pro Session, pro Request (One-Time), pro Aktion? One-Time-Test: denselben Token zweimal senden.
- Leakage: Steht der Token in der URL (Referer-Leak, Browser-History)? Wird er per CORS-lesbarem Endpoint oder JSONP ausgeliefert?

Ergebnis-Notiz pro Variante: HTTP-Status + wurde der Seiteneffekt ausgeführt (anschließend mit GET verifizieren, nicht aus der Response raten).

## 2. SameSite der Session-Cookies

Aus `Set-Cookie`-Headern oder Browser-DevTools (Application → Cookies) ablesen:

- `SameSite=Strict` / `=Lax` / `=None` (+`Secure` Pflicht bei None) / **Attribut fehlt komplett**.
- Fehlendes Attribut = Browser-Default: Chrome/Edge Lax (mit ~2-Minuten-Lax+POST-Fenster nach Cookie-Setzung), Firefox/Safari historisch None — Details und Fenster in `references/samesite-matrix.md`.
- Prüfen, ob die **tatsächlich gesendete** Session-Cookie das Attribut trägt — Apps setzen oft mehrere Cookies mit unterschiedlichen Attributen; die schwächste entscheidet, was cross-site mitreist.
- Zusatz-Cookie ohne SameSite (z. B. Legacy-Auth-Fallback) kann die ganze SameSite-Strategie aushebeln.

## 3. Origin / Referer

Testserie (jede Variante einzeln, Seiteneffekt verifizieren):

1. `Origin`-Header entfernen.
2. `Origin: null` (Sandboxed-iframe, `data:`-URL, Redirect-Kette erzeugen das).
3. `Origin: https://evil.com` — reflektiert der Server oder akzeptiert er trotzdem?
4. Subdomain-/Suffix-Tricks: `https://target.com.evil.com`, `https://eviltarget.com`, `https://target.com@evil.com`.
5. Wenn Origin geblockt aber Referer geprüft wird: `Referer` ganz weglassen (per `<meta name="referrer" content="no-referrer">` oder `Referrer-Policy: no-referrer` auf der Angreifer-Seite). Viele Implementationen prüfen Referer nur, wenn vorhanden.
6. Referer-Regex aushebeln: `https://evil.com/?target.com`, `https://evil.com/target.com/`.

## 4. Custom-Header-Pflicht

APIs verlangen oft `X-Requested-With`, `Authorization: Bearer …` oder `Content-Type: application/json` — das erzwingt einen CORS-Preflight und blockt klassische Form-CSRF. Prüfen:

- Ist der Header wirklich **Pflicht** oder wird der Request ohne ihn auch akzeptiert? Test: ohne Header senden.
- Ist das Bearer-Token wirklich nicht im Cookie? Wenn die App den Header aus einem Cookie befüllt (JS liest Cookie → setzt Header), schützt der Header nichts cross-site, weil der Angreifer den Cookie-Wert nicht kennt — **aber**: gilt das auch für den schreibenden Endpoint selbst, oder nimmt der Server das Token alternativ direkt aus dem Cookie? Test: Header weglassen, nur Cookie mitschicken lassen.

## 5. CORS

Nur relevant, wenn der Angreifer die Response lesen oder nicht-simple Requests senden will. Prüfen mit `Origin: https://evil.com`:

- Wird `Access-Control-Allow-Origin` reflektiert und `Access-Control-Allow-Credentials: true` gesetzt? → voller lesender + schreibender Cross-Origin-Zugriff (oft eigenständig kritisch, macht CSRF-Token auslesbar).
- Preflight-Antwort lesen: erlaubte Methoden und Header.

## 6. Content-Type-Erzwingung

Simple Requests (kein Preflight) erlauben nur `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`. Wenn der Endpoint `application/json` verlangt:

- Akzeptiert er den Body auch als `text/plain` mit JSON-Inhalt? (Viele Frameworks parsen trotzdem.)
- Gibt es eine Form-Variante derselben Aktion (klassischer View-Endpoint neben der API)?
- `enctype="text/plain"` Trick für JSON-ähnliche Bodies — siehe `assets/poc-json.html`.

## Bewertung

Ein Kandidat ist verwundbar, wenn nach Abarbeiten aller aktiven Schichten ein Cross-Site-Request ohne Mitwirken des Opfers (außer Seitenbesuch) den Seiteneffekt auslöst. GET-basierte Zustandsänderungen sind fast immer verwundbar, sobald SameSite nicht Strict ist — Top-Level-Navigation reicht (einfacher `<img>`/Link-Load).
