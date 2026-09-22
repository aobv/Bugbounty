# Field Notes — gelernte Bypasses

Lebendes Log. Nach jedem Hunt eintragen, was funktioniert hat. Keine Secrets, keine Zugangsdaten, keine PII.

## Regeln

1. **Jeder bestätigte Bypass wird eingetragen** — mit exaktem Blocker, gewinnender Klasse und finalem Payload.
2. **Auch Lehrstücke eintragen:** Klassen, die gegen ein Target nichts brachten (mit Grund) — erspart beim nächsten ähnlichen Stack Zeit.
3. **Deduplizieren:** gleicher Blocker + gleiche Lösung wie ein vorhandener Eintrag → Datum/Target an den bestehenden Eintrag anhängen statt neue Zeile.
4. **Promotion:** Muster, das 2× bei unterschiedlichen Targets gewirkt hat → als Zeile in `bypass-map.md` hochziehen und hier als "promoted" markieren.
5. **Review-Rhythmus:** nach jedem dritten Hunt die Tabelle auf veraltete Einträge prüfen.

## Tabelle

| Datum | Target | Blocker (exakt: was wurde gefiltert/kodiert) | Gewinnende Klasse | Finaler Payload | Notiz | Status |
|---|---|---|---|---|---|---|
| YYYY-MM-DD | beispiel.tld | `"` kodiert, `'` frei, `<script>` entfernt | Tag-Wechsel + Quote-Mix | `<svg onload=alert('DX_XSS@'+location.origin)>` | Filter lief nur einmal | promoted |
