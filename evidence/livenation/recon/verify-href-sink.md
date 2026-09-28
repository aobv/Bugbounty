# Verifikation: aurora `href`-Durchleitung → `javascript:`-URI-XSS

Die Hypothese aus `../offline-analysis.md`. Alles hier braucht Netz zum Ziel und
einen Browser; der Analyse-Container kann keinen dieser Schritte.

## Hypothese in einem Satz

`@ticketmaster/aurora` reicht `href`/`url` an neun Stellen ungefiltert an `<a>`
weiter und validiert nirgends das Scheme. Wenn eine Seite auf einem
In-Scope-Origin einen angreiferkontrollierten Wert in einen dieser Props gibt,
ist `href="javascript:…"` ein Ein-Klick-XSS in diesem Origin.

## Schritt 1 — Läuft aurora überhaupt auf dem Ziel?

Ohne das ist der Rest hinfällig. Im Bundle oder DOM nach Fingerprints suchen:

```bash
# aurora nutzt styled-components; Klassen tragen keinen Namen. Diese Marker
# stammen aus dem publizierten Source und sind stabiler:
grep -oE 'getRelByTarget|LinkItemContainer|RowOptionsLink|LinkCta|aurora' out/js/*.js | sort -u
```

Im Browser zusätzlich: `document.querySelectorAll('a[rel=noopener][target=_blank]')`
— aurora setzt `rel="noopener"` über `getRelByTarget()` automatisch, während
handgeschriebene Links das meist nur teilweise tun. Ein Origin, auf dem *jeder*
`target="_blank"`-Link `rel="noopener"` trägt, nutzt sehr wahrscheinlich aurora.

Wenn aurora nicht nachweisbar ist: Hypothese fallen lassen, nicht weiterbiegen.
Die generische Klasse (`<a href>` aus Parameter) trotzdem weiterverfolgen — sie
braucht aurora nicht.

## Schritt 2 — Wo kommt der Taint her?

Gesucht ist ein Pfad von einer unauthentifiziert kontrollierbaren Quelle in einen
der neun Props. Reihenfolge nach Aufwand:

1. **Query-Parameter** — billigster Fall, nur ein Link nötig. Aus
   `out/crawl/sink-candidate-urls.txt` die Kandidaten mit `url`, `redirect`,
   `next`, `return`, `returnUrl`, `continue`, `dest`, `target`, `goto`, `link`,
   `href`, `ref` nehmen.
2. **`location.hash`** — ebenfalls nur ein Link, und der Wert erreicht den Server
   nicht, umgeht also serverseitige Filter und WAF-Regeln komplett.
3. **API-/CMS-Felder** — Event-Titel, Venue-Beschreibung, Künstler-Links. Auf
   `royalarena.dk`, `onthewaterfrontfestival.com`, `lineup.com.mx` am
   wahrscheinlichsten, weil dort Redaktionsinhalte durchlaufen. Unauthentifiziert
   nur ausnutzbar, wenn das Feld ohne Login schreibbar ist — sonst kein Fall für
   diese Runde.

`signup.ticketmaster.com` zuerst: der Sign-Up-Verification-Flow ist per Definition
ohne Login erreichbar, und das Programm hat ihn eigens als Kampagnen-Target
ausgeschrieben.

## Schritt 3 — Taint bis in die Sink verfolgen

Nicht raten, hooken. `dom-sink-hooker` in die Seite laden und den Marker durch
den Parameter schicken:

```
https://<host>/<pfad>?<param>=aur0raPr0be1234
```

Der Hook loggt jeden Attribut-Write mit Stacktrace. Gesucht ist ein
`setAttribute("href", …)` oder ein React-Attribut-Write, dessen Wert den Marker
enthält. Der Stacktrace zeigt dann die Komponente.

Wichtig: ein durch die Hooks künstlich erzeugter Zustand ist **kein** Finding. Die
Hooks dienen dem Nachweis, dass der Wert ankommt — der Trigger muss danach ohne
sie funktionieren.

## Schritt 4 — Auslösen

Erst wenn Schritt 3 den Marker im `href` zeigt:

1. Scheme-Payload durch denselben Parameter.
2. Element im DOM prüfen: steht das Scheme wirklich im Attribut, oder hat React /
   ein Framework es weggeworfen? `document.querySelector('a[href^=j]').href`
3. Klicken. Kein Alert → Blocker exakt notieren (welches Zeichen, welches
   Keyword, was ersetzt wurde) und mit `waf-sanitizer-playbook` die nächste
   Technik-Klasse wählen. Persistenz-Mindestmaß: 5 Versuche über 3
   Technik-Klassen, bevor die Stelle als dicht gilt.
4. CSP gegenlesen (`out/headers/csp.txt`). `javascript:`-URIs fallen unter
   `script-src`; ein Origin ohne `unsafe-inline`, aber auch ohne `strict-dynamic`,
   verhält sich hier nicht wie erwartet — messen, nicht annehmen.

## Was das Ergebnis wert ist

Die Bewertung hängt am Origin, nicht am Payload:

- **`app.ticketmaster.*` / `app.livenation.com`** — Session-Origin. XSS trifft eine
  authentifizierte Session, das Programm nennt Authentication ausdrücklich als
  Interessengebiet. Hier liegt das Maximum.
- **`ticketmaster.com` / `livenation.com`** — Consumer-Origin, teilt Cookie-Domain
  mit den App-Origins. Für die Impact-Argumentation zählt, welche Cookies ohne
  `HttpOnly` und ohne `SameSite=Strict` auf `.ticketmaster.com` gesetzt sind — das
  aus Phase 1 belegen, nicht behaupten.
- **Venue-/Event-Sites** — ohne Session niedriges Ceiling. Als Beleg für ein
  systemisches Library-Problem trotzdem verwertbar.

Ein Klick ist nötig (`javascript:`-URI). Das gehört in den Report und in den
CVSS-Vektor (`UI:R`) — nicht verschweigen. Ein Triager, der eine überhöhte
Angabe findet, liest den Rest defensiv.

## Wenn es hält: Library-Argument mitliefern

Der Fix liegt nicht auf der Seite, sondern in aurora. Die neun Stellen aus
`../offline-analysis.md` mit Datei und Zeile in den Report nehmen und eine
zentrale Scheme-Allowlist in `getAsProp()` / `getRelByTarget()` vorschlagen —
dort ist die Härtung schon angesiedelt, nur am Scheme vorbei. Das macht aus einem
Einzelfund einen Klassenfund und ist der Teil, der die Severity trägt.
