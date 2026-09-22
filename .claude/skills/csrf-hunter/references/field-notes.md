# Field Notes — Gelerntes pro Programm/Target

Nach jedem Hunt pflegen. Format pro Eintrag:

## [Programm / Host] — YYYY-MM-DD

- **Kandidat:** Methode + Pfad + Aktion
- **Schutzschichten:** (Diagnose-Tabelle in Kurzform)
- **Funktioniert hat:** Leiter + Stufe + finale Request-Variante
- **Nicht funktioniert hat:** (mit Server-Reaktion — spart beim nächsten Mal Versuche)
- **Muster:** z. B. "Token nur bei DELETE validiert, nicht bei POST", "SameSite fehlt auf remember-me-Cookie"

---

## Wiederkehrende Muster (programmübergreifend)

- Token wird nur auf Existenz, nicht auf Bindung geprüft → eigener Token beim Opfer einsetzbar.
- Origin-Check: Substring-Match → `target.com.evil.com` durchgelassen.
- Referer-Check nur bei Vorhandensein → `no-referrer`-Meta entwaffnet ihn.
- SameSite-Attribut fehlt auf genau einem von mehreren Auth-Cookies.
- JSON-API parst `text/plain`-Bodies still mit.
- Bestätigungsdialog: Token nur im Lade-Schritt, Submit tokenlos.

(Eigene Funde darunter ergänzen; Muster, die sich zweimal wiederholen, in `bypass-leitern.md` hochziehen.)
