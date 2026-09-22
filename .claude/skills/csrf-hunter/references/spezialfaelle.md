# Spezialfälle

## Login-CSRF

Ziel: Opfer wird in den **Angreifer-Account** eingeloggt → Opfer gibt danach sensible Daten ein (Zahlungsdaten, Nachrichten, Aktivitätshistorie), die der Angreifer ausliest.

- Login-Form auf Token/Freifeld prüfen (Leiter A aus `references/bypass-leitern.md` — Login-Forms haben selten echte Token).
- PoC wie Form-CSRF, Ziel = Login-Endpoint, Credentials = eigene (Test-)Zugangsdaten. Erlaubt, weil nur eigene Accounts beteiligt sind.
- Impact im Report konkret machen: welche Daten fließen nach dem erzwungenen Login an den Angreifer?
- Nebeneffekt: frisch gesetzte Session-Cookies starten das Lax+POST-Fenster — Login-CSRF als Türöffner für Leiter B.3.

## Logout-CSRF

Meist niedrige Severity, aber: kann als Störung in Auth-Flows wirken (Session-Fixation-Ketten, Login-CSRF-Vorbereitung). Schnelltest mit `<img src="https://target/logout">`, wenn GET-basiert. Kein langer Aufenthalt hier — Zeit in Login-CSRF und SameSite-Lücken stecken.

## Cross-Site WebSocket Hijacking (CSWSH)

WebSocket-Handshake ist ein normaler HTTP-Request mit Cookies — SameSite greift zwar, aber:

1. Viele WS-Server prüfen `Origin` nicht. Test: Handshake mit `Origin: https://evil.com` senden.
2. Wenn Handshake akzeptiert: PoC-Seite öffnet `new WebSocket("wss://target/…")` aus Angreifer-Kontext; Browser hängt Cookies an, wenn SameSite es erlaubt (None oder same-site-Subdomain) oder der Server Origin ignoriert und keine Cookie-Auth verlangt (Token im Handshake? dann schauen, woher der Token kommt).
3. Token im ersten WS-Frame statt im Handshake → Origin-Prüfung ist die einzige Schranke. Fehlt sie → CSWSH.
4. Nachweis: aus Angreifer-Seite eine Nachricht im Namen des Opfers senden und Antwort lesen.

## Cookie-Tossing / Double-Submit-Brechung

Wenn das CSRF-Token per Double-Submit-Cookie läuft (Cookie-Wert = Body-Wert):

- Akzeptiert der Server **beliebige** Cookie-Werte (kein Signatur-Check)? Dann: eigene Cookie setzen und denselben Wert im Body mitschicken.
- Cookie-Setz-Vektor beim Opfer: kontrollierte Subdomain setzt `Domain=.target.com`-Cookie (überschreibt/speist das Token-Cookie) → Subdomain-Inventory, Static-Host-Uploads, XSS dort.
- Auch ohne Subdomain: manche Apps lesen das Token-Cookie via `document.cookie` und senden es als Header — dann reicht reines Setzen nicht, aber der Header-Schutz fällt weg, sobald der Server den Header-Wert nicht gegen ein serverseitiges Geheimnis prüft.

## OAuth/SAML-Login-CSRF

- `state`-Parameter fehlt oder wird nicht validiert → Angreifer leitet eigenen Auth-Code beim Opfer ein → Opfer-Session an Angreifer-Identität gebunden (Login-CSRF über SSO).
- Test: eigenen OAuth-Flow bis zum Callback fahren, Callback-URL (mit eigenem Code) beim Opfer im zweiten Profil laden. Wird eine Session aufgebaut → Finding.

## Multi-Step-Flows

Bestätigungsdialoge schützen nicht, wenn alle Schritte tokenlos sind: Schritt 1 (Formular laden) und Schritt 2 (Submit) beide automatisierbar per iframe-Kette oder zwei fetch-Requests. Beim Inventur-Schritt Flows immer bis zum Ende durchspielen und jeden Schritt einzeln auf Token prüfen — häufig hat nur Schritt 1 einen.

## GET mit Seiteneffekt

Systematisch suchen: alle GET-Routen der Inventur auf Zustandsänderung prüfen (Logout, E-Mail-Verifizierung, "delete?confirm=yes", Export-Trigger). Ein einziger reicht für ein Finding — SameSite=Lax lässt Top-Level-GET zu, also `<img>`, Link-Klick oder Redirect als Vektor.
