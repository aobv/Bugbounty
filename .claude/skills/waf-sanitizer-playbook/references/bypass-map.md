# Bypass-Map: Blocker → nächste Technik-Klassen

Pro Zeile: was der Filter tut → welche Klassen als Nächstes testen. Jede Klasse zählt als eigene Technik-Klasse im Persistenz-Mindestmaß. Vor jeder Zeile: Response-Diagnose (entfernt / kodiert / ersetzt / Request geblockt?).

## Diagnose zuerst: Wie blockiert der Filter?

| Beobachtung | Bedeutung | Konsequenz |
|---|---|---|
| Zeichen entfernt | strip-Filter | Verschachtelung, die nach Entfernung das Konstrukt ergibt (`<scr<script>ipt>`) |
| Zeichen kodiert (`<` → `&lt;`) | Encoding-Filter | Kontext prüfen: im JS-String ist `&lt;` wirkungslos, im HTML-Body auch — dann Ausbruchskontext wechseln |
| Zeichen ersetzt (durch `` o. ä.) | Ersetzungs-Filter | Testen, ob die Ersetzung selbst injizierbar ist |
| Request geblockt (403/406/Blockseite) | WAF | `waf-notes.md`, nicht App-Filter |
| Stille 200, Wert fehlt komplett | Serverseitige Validierung/Allowlist | erlaubte Werte-Menge erkunden (welche Tags/Attribute gehen durch?) |

## Zeichen-/Token-Filter

| Blocker | Nächste Technik-Klassen |
|---|---|
| `<` / `>` entfernt oder kodiert | Kontexte ohne `<`: Attribut-Ausbruch über Quote, Event-Handler in bereits erlaubtem Attribut, JS-String-Kontext, URL-Kontext · HTML-Entities senden, wenn Server/Template später dekodiert · Unicode-Varianten, die der Parser normalisiert |
| `"` und `'` gefiltert | Unquoted-Attribut-Werte · Backtick als JS-Delimiter · Entities im HTML-Kontext (`&quot;`, `&#39;`) · JS-String: Kommentar-Terminierung statt Quote-Escape |
| Backtick zusätzlich gefiltert | String-Concat aus Zeichencodes: `String.fromCharCode(...)` · Array-Join-Tricks · vorhandene Seiten-Strings wiederverwenden |
| `alert` / Keyword gefiltert | `top['al'+'ert']` · `self.alert` / `globalThis.alert` · Tagged Template `alert\`1\`` · `window['al'+'ert'].call()` · Indirektion über `(0,eval)` / `Function` |
| Klammern `()` gefiltert | Tagged Templates · String-Form von `setTimeout`/`setInterval` · `location=...`-Zuweisung · `onerror=alert;throw ...`-Stil · `valueOf`/`toString`-Überladung in Ausdruckskontexten |
| `<script>` gefiltert | Event-Handler-Tags: svg onload, img onerror, details ontoggle, video/source onerror, marquee onstart, input/select/textarea autofocus onfocus |
| `on*`-Handler gefiltert | `javascript:`-URLs in href/formaction/xlink:href · SVG-Animation (`<animate>`, `<set>`) · `<iframe srcdoc=...>` (Entities-kodiert) |
| `onerror` spezifisch gefiltert | Alternativ-Handler: onload, onbegin, ontoggle, onfocus+autofocus, onpointerover, onanimationstart (mit CSS), onpageshow |
| `svg`/`img` spezifisch gefiltert | details, marquee, video, audio, source, input, select, textarea, iframe, object, embed, a (href), math |
| Leerzeichen gefiltert | `/` zwischen Tag und Attribut · Tab/LF/FF (0x09/0x0A/0x0C) · `/**/` im JS-Kontext |
| `=` gefiltert | Kontexte ohne Zuweisung: vorhandenes Attribut nutzen, URL-Kontext · HTML-Entity für `=`, wenn später dekodiert |
| `javascript:` gefiltert | `java\tscript:` · `java&#09;script:` · Case-Mix · Whitespace/Newlines im Keyword · `data:` (Origin-Regel beachten) |
| Längenlimit | Kürzeste auto-führende Formen: `<svg onload=...>` · Marker verkürzen (alert ohne Origin nur als Sonde; Final-Proof braucht Origin) · Auslagerung in mehrere Attribute |

## Encoding-Ebenen (in dieser Reihenfolge eskalieren)

1. URL-Kodierung
2. Doppelte URL-Kodierung (wenn zweimal dekodiert wird — typisch bei Redirect-Handoffs)
3. HTML-Entities: dezimal, hex, hex ohne Semikolon
4. Unicode-Escapes — nur im JS-String-/Identifier-Kontext
5. Mixed Case bei Keywords — nur gegen primitive Regex-Filter
6. Null-Bytes / Overlong UTF-8 — gegen moderne Browser tot, gegen Server-Filter manchmal nicht; eine Stufe, dann weiter

## Strukturelle Umgehungen

- **Filter läuft einmal:** Verschachtelung, die nach Filterung das verbotene Konstrukt ergibt.
- **Reihenfolge:** Sanitize-then-Decode ist umgehbar (nach dem Sanitizer dekodierte Zeichen), Decode-then-Sanitize nicht. Immer zuerst die Reihenfolge feststellen.
- **Doppelte Normalisierung:** NFC/NFKC-Normalisierung nach dem Filter kann Zeichen erzeugen, die der Filter vorher nicht gesehen hat.
- **HPP:** Parameter doppelt senden; Stacks unterscheiden sich (erstes vs. letztes Vorkommen).
- **Content-Type-Wechsel:** JSON-Endpunkt zu text/html bringen (Accept-Header, `?format=`, Fehler provozieren). Reflected zählt erst bei text/html.
- **Charset:** fehlt die Charset-Deklaration, Kodierungs-Tricks prüfen. UTF-7 ist in modernen Browsern weitgehend tot — eine Probe, dann schließen.
- **DOM Clobbering:** Wenn der Filter Markup erlaubt, aber Attribute strippet: id/name-Clobbering gegen die Filter-Logik selbst (Filter liest `config.sanitize`, Clobbering überschreibt es).

## Regeln

- Ein Versuch = eine Klasse + ein dokumentierter Payload + Response-Unterschied. Ohne Doku zählt er nicht.
- Nie mehrere Klassen in einem Payload mischen — sonst weißt du nicht, was gewirkt hat.
- Gewinner nach dem Hunt in `field-notes.md`, wiederkehrende Muster hier hochziehen.
