# Client-Side Prototype Pollution

Grundregel: Pollution allein ist kein Finding. Erst die Kette zählt — **Verschmutzung haftet** + **Gadget zieht die Property in eine Sink** + **Opferpfad ohne Konsole**. Fehlt ein Glied, ist der Kandidat offen, nicht bestätigt.

## 1. Die drei Glieder sauber trennen

| Glied | Frage | Beleg |
|---|---|---|
| Pollution | Setzt die App selbst eine Property auf `Object.prototype`? | Konsolen-Test nach Abschnitt 3, nach normalem Seitenaufruf |
| Gadget | Liest irgendein Code diese Property und schiebt sie in eine Sink? | Treffer in `__xssDump(true)` |
| Opferpfad | Erreicht ein Opfer diesen Zustand über eine URL/Aktion, die du ihm schicken kannst? | Reproduktion in frischem Profil |

Drei getrennte Beobachtungen, drei getrennte Log-Einträge. Wer Glied 1 belegt und Glied 2 vermutet, hat nichts.

## 2. Injektionsvektoren

| Quelle | Form |
|---|---|
| Query-String | `?__proto__[KEY]=VAL` · `?__proto__.KEY=VAL` · `?constructor[prototype][KEY]=VAL` · `?constructor.prototype.KEY=VAL` |
| Verschachtelt unter einem harmlosen Parameter | `?opts[__proto__][KEY]=VAL` · `?a[b][__proto__][KEY]=VAL` |
| Hash | `#__proto__[KEY]=VAL` — erreicht den Server nie, also weder Server-Filter noch WAF; bei rein clientseitigen Parsern der erste Versuch |
| JSON-Body | `{"__proto__":{"KEY":"VAL"}}` · `{"constructor":{"prototype":{"KEY":"VAL"}}}` |
| Gespeicherte Blobs | localStorage-/sessionStorage-JSON, Cookie-JSON, `window.name` (JSON), Hydration-Blobs — alles, was `JSON.parse` durchläuft und danach gemerged wird |
| postMessage | `event.data` als Objekt oder JSON-String; Listener-Quelltext über `__pmDump()` lesen |

Verwundbare Verarbeitungsstellen: rekursive Merge-/Extend-/Clone-/Defaults-Routinen, Pfad-Setter (`set(obj,'a.b.c',v)`), Query-String-Parser mit Bracket-Syntax, Deep-Assign-Wrapper um `Object.assign`.

## 3. Haftet die Verschmutzung? — Konsolen-Test

Reihenfolge ist bindend, sonst misst du Müll:

1. Frischer Tab, Seite normal laden. Vorprobe: `({}).polluted_xss7q3z` → muss `undefined` sein.
2. Die Test-URL aufrufen bzw. den Flow durchlaufen, der den Wert verarbeitet — **die App macht die Verschmutzung, nicht du**.
3. Nachprobe: `({}).polluted_xss7q3z` → liefert sie den Wert, haftet die Pollution.
4. Zusätzlich `Object.prototype.polluted_xss7q3z` prüfen, um eine reine Instanz-Zuweisung auszuschließen.

```
https://HOST/PFAD?__proto__[polluted_xss7q3z]=xss7q3z
https://HOST/PFAD#__proto__[polluted_xss7q3z]=xss7q3z
https://HOST/PFAD?opts[__proto__][polluted_xss7q3z]=xss7q3z
https://HOST/PFAD?constructor[prototype][polluted_xss7q3z]=xss7q3z
```

**Pollution überlebt den Test.** Vor jedem weiteren Versuch harter Reload, sonst hältst du Reste des letzten Versuchs für einen neuen Treffer. Gespeicherte Vektoren (Storage, Cookie) gehören nach dem Test aufgeräumt.

## 4. Vektor blockiert → Leiter

Zählt als Blocker im Sinne des Persistenz-Mindestmaßes; Diagnose zuerst (entfernt / ersetzt / Request geblockt), Vorgehen wie in `../../waf-sanitizer-playbook/references/bypass-map.md`.

1. Schreibweise wechseln: Bracket ↔ Punkt.
2. `constructor[prototype]` statt `__proto__` (trifft Key-Blocklisten, die nur `__proto__` kennen).
3. Eine Ebene tiefer unter einen erlaubten Parameter hängen.
4. URL-Kodierung, dann doppelte URL-Kodierung des Schlüssels (greift bei Decode-nach-Filter).
5. Transportweg wechseln: Query → Hash → JSON-Body → Storage-Blob → postMessage.

## 5. Gadget-Suche im Bundle

Bundle vorher lesbar machen: `npx --no-install prettier --parser babel BUNDLE.js`. Namen sind minifiziert — such nach **String-Literalen und Strukturen**, nie nach sprechenden Bezeichnern.

| Ziel | Suchmuster |
|---|---|
| Direkter Bezug auf die Kette | `__proto__` · `constructor` · `prototype` als Literal |
| Vorhandener Schutz (Negativ-Befund) | `hasOwnProperty` · `Object.create\(\s*null\s*\)` · `Object.freeze` · `Map\(` |
| Merge-Kandidat (for-in ohne Guard) | `\bfor\s*\(\s*(?:var\|let\|const)\s+[\w$]+\s+in\s+[\w$]+\s*\)` |
| Rekursion im Merge | in derselben Funktion zusätzlich `typeof\s+[\w$]+\s*===?\s*['"]object['"]` |
| Pfad-Setter | `\.split\(\s*['"]\.['"]\s*\)` |
| Query-Parser mit Bracket-Syntax | `\.split\(\s*['"]&['"]\s*\)` in Verbindung mit `decodeURIComponent` |
| Options-Objekt mit Default-Fallback | `\|\|\s*\{\s*\}` · `\?\?\s*\{\s*\}` — dort greifen geerbte Properties |

## 6. Welche Properties ziehen in Sinks

Kein Katalog aus dem Gedächtnis — das sind Klassen, in denen du im konkreten Bundle nachsiehst:

| Gadget-Klasse | Typische Property-Namen | Sink am Ende der Kette |
|---|---|---|
| Template-/Renderer-Optionen | `template`, `html`, `content`, `innerHTML` | `innerHTML`, `insertAdjacentHTML` |
| Sanitizer-Config | `ALLOWED_TAGS`, `ALLOWED_ATTR`, `ADD_ATTR`, `WHOLE_DOCUMENT` | Sanitizer-Ausgabe → `innerHTML` (Config-Matrix: `../../waf-sanitizer-playbook/references/dompurify.md`) |
| Script-/Asset-Loader | `src`, `url`, `baseURL`, `basePath`, `nonce`, `integrity` | `script.src`, `setAttribute:src` |
| HTTP-Client-Optionen | `url`, `baseURL`, `method`, `headers` | `fetch`, `xhr.open` |
| Navigations-/Routing-Optionen | `to`, `from`, `redirect`, `next`, `returnUrl` | `location.assign`, `location.replace`, `a.href` |
| Feature-Flags / Kill-Switches | `debug`, `devMode`, `allowUnsafe`, `enableHtml`, `sanitize` | schaltet den unsicheren Zweig frei |
| Ausführungs-Optionen | `callback`, `handler`, `expression` | `Function`, `eval(indirect)`, `setTimeout(string)` |

Der stärkste Hebel ist meist nicht das Setzen eines Wertes, sondern das **Füllen einer Lücke**: Code prüft `opts.x`, `opts` hat kein eigenes `x` — die geerbte Property gewinnt.

## 7. Nachweis mit den Hooks

Der Trick: **der verschmutzte Wert ist der Marker.** Dann macht das Sink-Log die Kette sichtbar, ohne dass du sie erzählen musst.

1. Marker vor der Injektion setzen: `window.__XSS_MARKERS = ['DX_XSS','xss7q3z']`. `__xssMarkers()` reicht nicht — es ändert nur das Marker-Array von `sink-hook.js`, nicht das von `source-watch.js`.
2. Hooks in dieser Reihenfolge injizieren: `assets/hooks/sink-hook.js`, dann `assets/hooks/source-watch.js`, dann `assets/hooks/postmessage-watch.js`. Die Reihenfolge ist bindend — beide ersten Dateien definieren den Cookie-Descriptor neu und ketten nur so korrekt.
3. Flow mit `?__proto__[GADGET_PROPERTY]=xss7q3z` durchlaufen. Ladung so wählen, dass der Marker im Wert steht, nicht nur im Schlüssel.
4. `__xssDump(true)` — jeder tainted Eintrag ist ein belegtes Gadget. Sink-Name, Wert und Stacktrace (Datei:Zeile) in die Kandidaten-Matrix.
5. `__srcDump(true)` und `__srcSnapshot()` zeigen, über welche Source der Wert hereinkam — bei Hash-Vektoren steht er in `location.hash`.
6. Kommt der Wert per `event.data`: `__pmDump()` liefert den Listener-Quelltext, dort die Origin-Prüfung lesen.
7. Feuert kein Hook, obwohl die Aktion sichtbar passiert: `troubleshooting.md` Abschnitt 1 abarbeiten, bevor du den Kandidaten schließt.

## 8. Abschluss und Verbote

- **Verboten:** ein Finding aus einem Zustand, den du selbst in der Konsole gesetzt hast. `Object.prototype.x = 1` von Hand ist ein Selbsttest des Gadgets, kein Nachweis der Pollution. Der Vektor muss durch die App laufen.
- **Verboten:** eine Property als Gadget behaupten, ohne Sink-Log. Prototyp-Verschmutzung ohne beobachtete Sink ist kein XSS.
- Finding erst bei beobachteter Ausführung im Opferkontext mit Origin-Marker (`MARKER` = `alert('DX_XSS@'+location.origin)`) und Screenshot. Braucht das Opfer die Konsole, ist es kein Finding.
- Sauber geschlossen wird so: "Pollution über `__proto__[x]` im Query bestätigt (Konsolen-Nachprobe), N Gadget-Klassen aus Abschnitt 6 im Bundle geprüft, kein Treffer in `__xssDump(true)`" — mit Vektor, geprüften Klassen und Datum. Das negative Ergebnis ist verwertbar und gehört in die Matrix.
