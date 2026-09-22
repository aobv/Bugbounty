# SameSite-Verhalten: Entscheidungsmatrix

SameSite steuert nur, ob **Cookies** cross-site mitreisen. Es schützt nicht vor Angriffen aus same-site Kontext (Subdomain!) und nicht gegen Header-/Token-basierte Auth, die der Angreifer nicht braucht.

## Attribut → Cross-Site-Verhalten

| Cookie-Attribut | Top-Level-Navigation GET | Top-Level POST | Subresource / iframe / fetch |
|---|---|---|---|
| `SameSite=Strict` | nein | nein | nein |
| `SameSite=Lax` | **ja** | nein* | nein |
| `SameSite=None; Secure` | ja | ja | ja |
| Attribut fehlt (Chrome/Edge ≥ 80) | wie Lax | **ja, ~2 Min nach Set-Cookie** ("Lax+POST") | nein |
| Attribut fehlt (ältere Firefox/Safari) | wie None | wie None | wie None |

\* Ausnahme Lax+POST-Neusetzfenster (s. u.).

## Das Lax+POST-Fenster (Chrome)

Setzt der Server ein Cookie **ohne** SameSite-Attribut, sendet Chrome es für ca. 2 Minuten auch bei Top-Level-**POST** mit. Ausnutzen:

- Jeder Endpoint, der ein Cookie neu setzt/refresht, verlängert das Fenster — Inventur danach durchsuchen (`Set-Cookie` in Responses greppen).
- Login-CSRF oder ein OAuth/SSO-Redirect kurz vor dem Angriff erzeugt frische Cookies beim Opfer.
- Test: Cookie setzen lassen, sofort Cross-Site-POST, Seiteneffekt prüfen. Timing im PoC automatisierbar (Login-Redirect → Angriffsseite).

## Site ≠ Origin

"Site" = eTLD+1 (plus Scheme-Nähe). Konsequenzen:

- `app.target.com` → `api.target.com` ist **same-site**: SameSite=Strict schützt dort nicht. Jede kontrollierte Subdomain (XSS, Static-Host mit Upload, Subdomain-Takeover, Staging im gleichen eTLD+1) ist ein CSRF-Startpunkt.
- Public Suffix List beachten: bei `target.github.io`-artigen Hosts ist die Site der Suffix-Host — Angreifer-Subdomain dann **nicht** same-site.
- Cookie-Scope: `Domain=.target.com`-Cookies reisen zu allen Subdomains → Cookie-Tossing (`references/spezialfaelle.md`).

## Praktischer Testablauf

1. DevTools → Application → Cookies: Attribut jeder Session-Cookie notieren. Fehlt es, Browser-Default annehmen und Fenster testen.
2. Cross-Site-Simulation: PoC-Seite auf eigener Domain/andersem Port hosten (nicht `file://` — manche Browser senden dort Cookies inkonsistent), mit zweitem Profil beim Target eingeloggt.
3. In der Angreifer-Session prüfen (DevTools → Network → "Cookies" des Requests bzw. serverseitiger Log): ist die Session-Cookie mitgereist? Das ist die Binärentscheidung — nicht aus SameSite-Attribut raten.
4. Negative Chrome-Tests in Firefox wiederholen (und umgekehrt): Default-Unterschiede entscheiden Findings. Report immer mit Browser + Version.

## Häufige Fehldiagnosen

- "SameSite=Lax, also sicher" — falsch bei GET-Routen mit Seiteneffekt und bei same-site-Subdomain-Kontrolle.
- "SameSite fehlt, also sicher" — Chrome-Default ist Lax, aber Lax+POST-Fenster + andere Browser aufhebeln das.
- Session-Cookie ist Strict, aber ein zweites Auth-Cookie ("remember me") ist None — das schwächste Auth-Cookie gewinnt.
