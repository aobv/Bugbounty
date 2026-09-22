# WAF-Notizen

## Identifikation

| Signal | Hinweis auf |
|---|---|
| `cf-ray`, `cf-cache-status`, Server `cloudflare` | Cloudflare |
| `x-akamai-*`, `akamai` im Server-Header, charakteristische Reference-ID-Blockseite | Akamai |
| `x-amzn-*`, `awselb`, generische 403 ohne Body | AWS (WAF/CloudFront/ALB) |
| `x-iinfo`, `incap_ses_*`-Cookies | Imperva/Incapsula |
| `x-sucuri-*` | Sucuri |
| `server: awselb`, ModSecurity-Fehlerseiten mit Regel-IDs | ModSecurity/CRS |

Verhaltensunterschiede festhalten: blockt der WAF den ganzen Request (403/406, Blockseite) oder filtert die App still (200, veränderter Body)? Das sind zwei verschiedene Gegner — Verwechslung ist der häufigste Analysefehler.

## Umgehungsklassen (produktübergreifend, in Eskalationsreihenfolge)

1. **Encoding-Stufen:** URL → doppelte URL → HTML-Entities → Mixed Case (Details: `bypass-map.md`).
2. **Keyword-Splitting:** Zeichen einfügen, die der WAF-Normalizer entfernt, der Browser aber toleriert (Kommentare, Whitespace-Varianten, `/`).
3. **Struktur:** HPP (Parameter doppelt), Array-Notation (`x[]`), JSON-Body statt Formular, Verschachtelung gegen Einmal-Filter.
4. **Content-Type-Wechsel:** JSON-Endpunkt zur HTML-Ausgabe bewegen; Reflected-XSS zählt erst bei `text/html`.
5. **Signatur-Lücken:** seltene Tags/Event-Handler außerhalb der Signatur-DB (Katalog: `payload-ladders.md`).
6. **Inspektions-Limits:** manche WAFs prüfen nur die ersten N KB eines Bodies — Padding als letzte Klasse, nie als erste.
7. **Alternativ-Endpunkte:** derselbe Parameter auf einem anderen Host/Endpoint ohne WAF-Front (Asset-Inventar aus dem Recon prüfen).

## Produkt-Erfahrungswerte (immer verifizieren, nie annehmen)

- **Cloudflare:** streng bei bekannten Keywords in bekannten Kombis, nachgiebiger bei Struktur-Tricks und seltenen Handlern. Managed Rules vs. Custom Rules unterscheiden.
- **Akamai:** kontextsensitive Regeln; Blockseiten typisch formatiert mit Reference-ID.
- **AWS WAF:** häufig Standard-Regelsätze (AWS Managed Rules) mit bekannten Encoding-Lücken.
- **ModSecurity (CRS):** Paranoia-Level entscheidet; Default-Installationen lassen viel durch; Anomaly-Scoring beachten (viele kleine Signale addieren sich).
- **Imperva:** verhaltensbasiert; Rate-Auslösung beachten, Tests verteilen.

## Regeln

1. Programm-Policy zu WAF-Evasion zuerst prüfen (Hunt-Prompt, Harte Regeln). Dokumentieren, Policy prüfen, nicht eskalieren.
2. Jeder WAF-Versuch ist ein Request — Massen-Requests verboten. Klassen nacheinander, nicht parallel.
3. Ein dokumentierter WAF-Block mit erschöpfter Klassen-Liste ist ein valides Matrix-Ergebnis ("CSP/WAF blockiert"), kein Misserfolg.
