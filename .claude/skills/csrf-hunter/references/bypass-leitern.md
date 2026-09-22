# Bypass-Leitern pro Schutzschicht

Von oben nach unten abarbeiten. Ein Versuch = eine Annahme. Jeder Versuch: Request-Variante + Server-Status + Seiteneffekt (ja/nein, per GET verifiziert) notieren.

## Leiter A — CSRF-Token vorhanden

1. Token-Parameter/Header komplett entfernen.
2. Token leer senden (`csrf=`).
3. Token verändern (letztes Zeichen kippen, Länge halten).
4. Gültigen Token aus **eigener zweiter Session** einsetzen (fehlende User-Bindung).
5. Token eines anderen Endpunkts derselben Session einsetzen (fehlende Aktions-Bindung).
6. One-Time-Token zweimal verwenden (Replay).
7. Token-Slot anderer HTTP-Methode: Body-Token in Query verschieben, Header-Token als Body-Parameter (und umgekehrt) — manche Backends lesen "Token von irgendwo".
8. Double-Submit prüfen: Cookie-Wert selbst setzen (Cookie-Tossing über Subdomain, siehe `references/spezialfaelle.md`) und denselben Wert im Body mitschicken.
9. Token-Leak suchen: CORS-reflektierender Endpoint, JSONP, postMessage, URL-Parameter → Referer. Geleakter Token + PoC = vollwertiges Finding.
10. DELETE/PUT als POST mit `_method=delete` / `X-HTTP-Method-Override` senden — Token-Prüfung hängt manchmal nur an der "echten" Methode.

## Leiter B — SameSite

Voraussetzungen und Fenster in `references/samesite-matrix.md` nachschlagen, dann:

1. **GET-Umstellung:** Gibt es dieselbe Aktion als GET-Route (Rails/Laravel/Django liefern oft beides)? SameSite=Lax lässt Cookies bei Top-Level-GET mitreisen → `<img>`/Redirect/Link genügt.
2. **Method-Override:** POST-Form mit `_method=patch` o. ä. — serverseitig PATCH, browserseitig Top-Level-POST … beachten: Lax sendet Cookies bei Top-Level-POST **nicht** (außer Lax+POST-Neusetzfenster). Override hilft nur, wenn eine GET-Route existiert oder das Fenster genutzt wird.
3. **Lax+POST-Fenster** (Chrome, ca. 2 Min nach Cookie-Setzung): Opfer-Login frisch erzwingen — Login-CSRF oder OAuth-Redirect-Kette direkt vor dem Angriff; oder eine Endpoint finden, der ein Cookie neu setzt (`Set-Cookie` refresht das Fenster).
4. **Cookie ohne SameSite:** Alle Auth-relevanten Cookies auf fehlendes Attribut prüfen (ältere Safari/Firefox-Versionen: kein Attribut = None-Verhalten).
5. **Sibling-/Subdomain-Kontext:** SameSite zählt die **Site** (eTLD+1), nicht den Origin. Von einer anderen Subdomain des Targets aus (XSS dort, kontrollierter Content, Subdomain-Takeover) gelten Requests als same-site → SameSite wirkungslos. Subdomain-Inventory des Scopes abklappern.
6. **Cross-scheme:** `http://` → `https://` galt lange als same-site; nur wo der Server noch HTTP annimmt und der Browser das Cookie sendet, relevant — testbar, wenn Target beides serviert.

## Leiter C — Origin/Referer-Prüfung

1. Header ganz entfernen (viele prüfen nur bei Vorhandensein).
2. `Origin: null` via sandboxed iframe (`sandbox="allow-scripts allow-forms"`) oder Redirect-Kette.
3. Erlaubte-Liste aushebeln: Prefix/Suffix (`target.com.evil.com`, `eviltarget.com`), Userinfo (`target.com@evil.com`), Punkt-Tricks.
4. Regex-Raterei systematisch: wird `target.com` nur als Substring gesucht? → `https://target.com.attacker.tld`. Wird am Anfang verankert? → `https://target.comX…`.
5. Referer statt Origin: `<meta name="referrer" content="no-referrer">` im PoC → Header fehlt → akzeptiert?
6. Interne/Partner-Origins in der Allowlist (staging, CDN, Static-Host): liegt dort XSS oder offener Redirect? → legitim aussehender Origin.

## Leiter D — Custom-Header / API-Pflicht

1. Request ohne den Header senden — oft ist er Konvention, nicht Validierung.
2. Token-Quelle prüfen: liest der Server `Authorization` alternativ aus Cookie/Query (`?access_token=`)?
3. Endpoint-Duplikate: gleiche Aktion an klassischem Form-Endpoint (`/settings` vs `/api/v2/settings`), älterer API-Version, Mobile-Endpoint.
4. CSWSH prüfen, wenn Aktion über WebSocket läuft → `references/spezialfaelle.md`.

## Leiter E — Content-Type / JSON

1. JSON-Body mit `Content-Type: text/plain` senden (kein Preflight nötig) — Framework parst häufig trotzdem.
2. `application/x-www-form-urlencoded` mit `{"json":"payload"}`-Struktur oder Parameter-Mapping (`user[email]=x`) — Rails/Laravel/Django mappen Form-Felder oft auf dieselben Handler.
3. `enctype="text/plain"`-Form, die syntaktisch gültiges JSON erzeugt (`assets/poc-json.html`).
4. `multipart/form-data` mit JSON-Part — manche Parser akzeptieren gemischte Parts.

## Abbruchkriterium

Erst nach Erfüllung des Mindestmaßes (5 Versuche / 3 Schichten, im Pflicht-Workflow) darf ein Kandidat als nicht verwundbar geschlossen werden — mit Diagnose-Tabelle als Beleg.
