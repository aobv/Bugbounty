# Pipeline: Stufe für Stufe, mit und ohne Standard-Binaries

Jede Stufe zweigleisig. Spalte "Binaries" gilt nur, wenn `command -v` das Werkzeug wirklich findet. Spalte "Fallback" braucht nur curl, python3, node, npx, jq — deren Vorhandensein ist geprüft, ebenso die Syntax der Snippets. Die netzabhängigen Fallbacks (crt.sh, Wayback) sind hier nicht end-to-end gelaufen; Rückgabeformat beim ersten Lauf mit Egress gegen die echte Antwort prüfen.

| Stufe | Binaries (falls vorhanden) | Fallback (nur curl/python3/node/jq) |
|---|---|---|
| 0 Scope | — | Checkliste unten, manuell |
| 1 Subdomains | `subfinder`, `assetfinder`, `dnsx` | crt.sh + `jq`, DNS-Bruteforce über `socket.getaddrinfo` |
| 2 Live-Hosts | `httpx` | `curl` + `xargs -P`, Header und Titel selbst schneiden |
| 3 URLs/Historie | `gau`, `waybackurls` | Wayback-CDX-JSON + `jq` |
| 4 Crawl | `katana` | Chromium über Playwright (`capture.js`) |
| 5 JS/Source Maps | — | `curl` + python (`unmap.py`), `prettier` zum Beautifyen |
| 6 Endpunkte/Routen | `LinkFinder`, `SecretFinder` | `grep -P` / python-Regex, siehe `js-und-sourcemaps.md` |
| 7 Directory-Fuzzing | `ffuf` | asyncio-Fuzzer mit Soft-404-Baseline, siehe `ohne-tools.md` |

## 0 — Scope-Prüfung (vor dem ersten aktiven Request)

Auf der Programmseite nachlesen und beantworten. Was dort nicht steht, wird als offene Frage notiert — nicht geraten, nicht aus anderen Programmen übertragen.

1. Welche Domains und Wildcards sind **in Scope**, welche explizit **out of scope**? Wildcards auflösen, bevor irgendein Host geprobt wird.
2. Ist **automatisiertes Scannen/Fuzzing** erlaubt, und mit welchem Rate-Limit? Falls nein: Stufe 7 entfällt, Stufe 2 sequenziell mit Delay.
3. Fordert das Programm einen **Identifikations-Header**? Format und Wert der Programmseite haben Vorrang vor jedem Default.
4. Sind **Testaccounts** vorgesehen, dürfen eigene angelegt werden, ist eine Kennzeichnung gefordert?
5. Welche Varianten sind überhaupt **erstattungsfähig**? Severity-Grundlage der Policy lesen (CVSS, eigene Tabelle, Kombination).
6. Gibt es **bekannte oder bereits gemeldete** Issues, die Pfade ausschließen?

Default-Kennung, solange die Policy nichts anderes fordert: `User-Agent: denibkv-hackerone-research`. Fehlt eine Vorgabe auf der Seite, wird der Default benutzt **und** im Protokoll vermerkt, dass keine Vorgabe gefunden wurde — damit die Annahme sichtbar bleibt.

## 1 — Subdomains

Mit Binaries:

```bash
subfinder -d APEX -all -silent  >> subs.txt   # jede Zeile nur ausfuehren, wenn
assetfinder --subs-only APEX    >> subs.txt   # command -v das Binary wirklich findet
sort -u subs.txt | dnsx -silent -a -resp > resolved.txt
```

Fallback — das `%` im Wildcard muss als `%25` kodiert sein, sonst schluckt es curl:

```bash
curl -sS --compressed --max-time 60 --retry 3 --retry-delay 5 \
  -A 'denibkv-hackerone-research' \
  'https://crt.sh/?q=%25.APEX&output=json' -o crtsh.json

jq -r '.[].name_value, .[].common_name' crtsh.json \
  | tr 'A-Z' 'a-z' | sed 's/^\*\.//' \
  | grep -E '^[a-z0-9._-]+$' | sort -u > subs-ct.txt
```

`name_value` kann mehrere Namen newline-separiert in **einem** Feld tragen; `jq -r` gibt die Newlines aus, `sort -u` zerlegt sie danach korrekt. Gesichert sind `q=` und `output=json`. **Vor Gebrauch verifizieren:** `&exclude=expired`, `&identity=`. crt.sh ist notorisch langsam und zeitweise down — ein leeres Ergebnis ist ein Quellen-Ausfall, nie "keine Subdomains".

CT-Alternativen, Format **vor Gebrauch verifizieren**: `api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&expand=dns_names`, Passive-DNS von `otx.alienvault.com`. Beide brauchen ggf. Key und Rate-Limit-Handling.

**Wildcard-Check ist Pflicht vor jedem Bruteforce**, sonst ist jeder Treffer wertlos:

```bash
python3 -c "
import socket
try: print(socket.getaddrinfo('zzq7x3-nonexistent.APEX',None)[0][4][0],'WILDCARD-VERDACHT')
except socket.gaierror: print('NXDOMAIN (kein Wildcard)')"
```

DNS-Bruteforce ohne `dnsx`: Snippet in `ohne-tools.md` Abschnitt 2. `dig`, `nslookup` und `host` sind hier **nicht** installiert — DNS läuft über python.

## 2 — Live-Hosts

Mit Binaries:

```bash
httpx -l subs.txt -silent -status-code -title -tech-detect -web-server \
      -include-response-header -json -o hosts.json     # nur wenn installiert
```

Fallback: `ohne-tools.md` Abschnitt 3. Pro Host zu erfassen: Status, effektives Redirect-Ziel, Titel, `Server`, `Content-Security-Policy`, `Content-Security-Policy-Report-Only`, `Set-Cookie`, `Access-Control-Allow-Origin`, `X-Frame-Options`, `X-Content-Type-Options`.

Zwei Fallen: `curl -D` schreibt bei `-L` die Header **aller** Hops in dieselbe Datei — `grep -im1` liefert dann den Header des Redirects, nicht des Ziels; für das CSP des Endziels ein zweiter Aufruf gegen `%{url_effective}` ohne `-L`. Und `-P 10` ist eine Obergrenze, die gegen die Programmregeln zu halten ist; im Zweifel `-P 3` plus Delay.

CSP steht oft zusätzlich in `<meta http-equiv>`. Nur eine der beiden Quellen zu lesen unterschlägt eine Schutzschicht — der Crawl in Stufe 4 fängt beide.

## 3 — URLs und Historie

Mit Binaries: `gau APEX`, `waybackurls APEX`.

Fallback:

```bash
curl -sS --compressed --max-time 120 -A 'denibkv-hackerone-research' \
  'https://web.archive.org/cdx/search/cdx?url=APEX&matchType=domain&output=json&fl=original,mimetype,statuscode,timestamp&collapse=urlkey&filter=statuscode:200&limit=50000' \
  -o cdx.json
```

`output=json` liefert **Array-of-Arrays mit Kopfzeile als erstem Element** — wer sie nicht abwirft, bekommt `original` als erste "URL":

```bash
jq -r '.[1:][] | .[0]' cdx.json | sort -u                          # alle URLs
jq -r '.[1:][] | select(.[1]|test("javascript")) | .[0]' cdx.json  # nur JS
jq -r '.[1:][] | .[0] | select(test("\\?"))' cdx.json | sort -u    # parametrisiert = Kandidaten
```

**Vor Gebrauch verifizieren:** `matchType=domain` gegen `url=*.APEX`, negierende Filter (`filter=!mimetype:image/.*`), Pagination (`&page=N`, `&showNumPages=true`). Sequenziell abfragen, nicht parallel — die Rate-Limits sind real.

Fällt das CDX-Archiv aus, bleiben als Ersatz: Crawl (Stufe 4), `robots.txt`, `sitemap.xml`, `/.well-known/`, und die aus Bundles und Source-Maps extrahierten Pfade (Stufe 5/6). Common-Crawl-Index als dritte Quelle — Format **vor Gebrauch verifizieren**.

## 4 — Crawl

Mit Binary: `katana -u https://TARGET -jc -kf all -silent`.

Fallback: Chromium über Playwright. Das Modul liegt global, der Aufruf braucht deshalb zwingend `NODE_PATH`:

```bash
NODE_PATH=$(npm root -g) node capture.js https://TARGET/ ./recon-out
```

Liefert in einem Durchlauf, was `katana` + `httpx` + manuelles Header-Lesen sonst getrennt liefern: alle JS-Assets inklusive lazy nachgeladener Chunks, XHR/fetch/WebSocket-Ziele, Inline-Scripts und CSP aus Header **und** `<meta>` gleichzeitig. Gerüst und Fallstricke in `js-und-sourcemaps.md` Abschnitt 1. Das Python-Modul `playwright` ist hier nicht installiert — Playwright nur über Node ansteuern.

## 5–7

Source Maps, Endpunkt- und Secret-Regex, Routen-Enumeration: `js-und-sourcemaps.md`. Directory-Fuzzing ohne `ffuf`: `ohne-tools.md` Abschnitt 5. Upload-Flächen aus dem Crawl: `upload-vektoren.md`.

## Nicht ersetzbar — ehrlich benennen

- **CNAME-, NS- und TXT-Records.** `getaddrinfo` folgt CNAMEs, liefert aber nur A/AAAA. Ohne `dig` oder DoH ist Subdomain-Takeover-Erkennung nicht sauber machbar. DoH über `curl` ist ein Ausweg — Format **vor Gebrauch verifizieren**.
- **Vulnerability-Templates (`nuclei`).** Kein Ersatz vorhanden. Für einen XSS-Hunt kein Verlust: blindes Spray ist ohnehin verboten.
- **Verteilte Massen-Enumeration.** Die python/curl-Wege sind deutlich langsamer. Bei einem einzelnen Programm mit Rate-Limits ist das irrelevant bis vorteilhaft.
