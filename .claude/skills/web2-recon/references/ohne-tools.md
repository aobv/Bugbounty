# Fallback: Recon ohne ein einziges Go-Binary

Alle Snippets hier sind in einer Umgebung ohne `subfinder`, `httpx`, `katana`, `gau`, `waybackurls`, `ffuf`, `dnsx`, `assetfinder`, `nuclei` — und ohne `dig`, `nslookup`, `host` — lauffähig getestet. Gebraucht werden nur `curl`, `python3`, `node`, `npx`, `jq`, `grep -P`.

Vor dem ersten Aufruf: Scope-Checkliste aus `pipeline.md` Abschnitt 0. `APEX` und `TARGET` sind Platzhalter, keine Beispiele.

## 1 — Subdomains aus CT-Logs

```bash
UA='denibkv-hackerone-research'
curl -sS --compressed --max-time 60 --retry 3 --retry-delay 5 -A "$UA" \
  'https://crt.sh/?q=%25.APEX&output=json' -o crtsh.json

jq -r '.[].name_value, .[].common_name' crtsh.json \
  | tr 'A-Z' 'a-z' | sed 's/^\*\.//' \
  | grep -E '^[a-z0-9._-]+$' | sort -u > subs-ct.txt
wc -l < subs-ct.txt
```

`%` muss als `%25` in der URL stehen. Leeres Ergebnis = Quellen-Ausfall, nicht "keine Subdomains".

## 2 — DNS-Bruteforce über getaddrinfo

Zuerst der Wildcard-Check, sonst ist jedes Ergebnis Müll:

```bash
python3 -c "
import socket
try: print(socket.getaddrinfo('zzq7x3-nonexistent.APEX',None)[0][4][0],'WILDCARD-VERDACHT')
except socket.gaierror: print('NXDOMAIN (kein Wildcard)')"
```

`resolve.py`:

```python
#!/usr/bin/env python3
"""DNS-Bruteforce ohne dnsx. Nutzung: resolve.py <wordlist> <apex> [workers]"""
import socket, sys, concurrent.futures as cf

def r(name):
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        return name, sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return None

def main(wl, apex, workers=50):
    socket.setdefaulttimeout(3)
    names = [f'{w.strip()}.{apex}' for w in open(wl) if w.strip() and not w.startswith('#')]
    with cf.ThreadPoolExecutor(max_workers=int(workers)) as ex:
        for res in ex.map(r, names):
            if res:
                print(f'{res[0]}\t{",".join(res[1])}')

if __name__ == '__main__':
    main(*sys.argv[1:])
```

Grenze: `getaddrinfo` folgt CNAMEs, liefert aber nur A/AAAA. CNAME-Ziel, NS und TXT siehst du damit nicht — Takeover-Kandidaten sind so nicht sauber erkennbar. Ohne Wordlisten auf dem System (`/usr/share/wordlists` und SecLists fehlen) kommt die Liste aus dem eigenen Recon: Pfade und Hostnamen aus CDX, Bundles und Source-Map-`sources`. Das ist ohnehin die bessere Liste als eine generische.

## 3 — Live-Host-Probing mit curl

```bash
#!/usr/bin/env bash
# Nutzung: cat hosts.txt | ./probe.sh  ->  TSV: host status server redirect titel csp
probe() {
  h="$1"
  for scheme in https http; do
    out=$(curl -sS -o /tmp/body.$$ -D /tmp/hdr.$$ \
          --max-time 12 --connect-timeout 6 -L --max-redirs 3 \
          -A 'denibkv-hackerone-research' \
          -w '%{http_code}\t%{url_effective}\t%{size_download}' \
          "$scheme://$h/" 2>/dev/null) || continue
    code=$(cut -f1 <<<"$out"); eff=$(cut -f2 <<<"$out")
    [ "$code" = "000" ] && continue
    srv=$(grep -im1 '^server:'                  /tmp/hdr.$$ | tr -d '\r' | cut -d' ' -f2-)
    csp=$(grep -im1 '^content-security-policy:' /tmp/hdr.$$ | tr -d '\r' | cut -c1-160)
    ttl=$(tr -d '\n' < /tmp/body.$$ | grep -oiP '<title[^>]*>\K.*?(?=</title>)' | cut -c1-80)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$code" "${srv:--}" "${eff:--}" "${ttl:--}" "${csp:--}"
    rm -f /tmp/body.$$ /tmp/hdr.$$; return
  done
  rm -f /tmp/body.$$ /tmp/hdr.$$
}
export -f probe
xargs -P 10 -I{} bash -c 'probe "$@"' _ {}
```

Status `000` heißt tot oder geblockt — übersprungen, nie als Ergebnis gewertet. Bei `-L` stammen die gegriffenen Header vom **ersten** Hop; für das CSP des Endziels ein zweiter Aufruf gegen `%{url_effective}` ohne `-L`. `-P 10` nur, wenn die Programmregeln Automatisierung in dieser Größenordnung decken.

## 4 — Historische URLs aus dem CDX-Archiv

```bash
curl -sS --compressed --max-time 120 -A 'denibkv-hackerone-research' \
  'https://web.archive.org/cdx/search/cdx?url=APEX&matchType=domain&output=json&fl=original,mimetype,statuscode,timestamp&collapse=urlkey&filter=statuscode:200&limit=50000' \
  -o cdx.json

jq -r '.[1:][] | .[0]' cdx.json | sort -u > urls-all.txt
jq -r '.[1:][] | .[0] | select(test("\\?"))' cdx.json | sort -u > urls-param.txt
jq -r '.[1:][] | select(.[1]|test("javascript")) | .[0]' cdx.json | sort -u > urls-js.txt
```

Die Kopfzeile ist das erste Array-Element und muss mit `.[1:]` abgeworfen werden. `urls-param.txt` ersetzt zusammen mit dem Crawl das, wofür sonst `gau` und `katana` gebraucht werden — das sind die Reflection-Kandidaten.

Parameter-Namen für die spätere Reflection-Sonde herausziehen:

```bash
python3 - urls-param.txt <<'PY'
import sys, collections
from urllib.parse import urlsplit, parse_qsl
c = collections.Counter()
for line in open(sys.argv[1]):
    for k, _ in parse_qsl(urlsplit(line.strip()).query, keep_blank_values=True):
        c[k] += 1
for k, n in c.most_common():
    print(f'{n}\t{k}')
PY
```

## 5 — Directory-Fuzzing ohne ffuf

```python
#!/usr/bin/env python3
"""Fuzzing mit Soft-404-Baseline. Nutzung: fuzz.py <base> <wordlist> [conc] [rps]"""
import asyncio, sys, ssl, random, string, urllib.request, urllib.error, hashlib
from concurrent.futures import ThreadPoolExecutor

UA = 'denibkv-hackerone-research'

def fetch(url, timeout=10):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            b = r.read(4096)
            return r.status, len(b), hashlib.sha1(b).hexdigest()[:10]
    except urllib.error.HTTPError as e:
        b = e.read(4096)
        return e.code, len(b), hashlib.sha1(b).hexdigest()[:10]
    except Exception:
        return None

async def main(base, wl, conc=15, rps=10):
    base = base.rstrip('/')
    loop = asyncio.get_running_loop()
    ex = ThreadPoolExecutor(max_workers=int(conc))
    sem = asyncio.Semaphore(int(conc))
    delay = 1.0 / float(rps)                       # Rate-Limit: Programmregeln beachten

    rnd = ''.join(random.choices(string.ascii_lowercase, k=16))
    base_sig = await loop.run_in_executor(ex, fetch, f'{base}/{rnd}')
    print(f'# Baseline (Zufallspfad): {base_sig}')

    async def one(w):
        async with sem:
            await asyncio.sleep(delay)
            r = await loop.run_in_executor(ex, fetch, f'{base}/{w}')
            if not r:
                return
            if base_sig and r[0] == base_sig[0] and r[2] == base_sig[2]:
                return                              # identische Soft-404-Seite
            print(f'{r[0]}\t{r[1]}\t/{w}')

    words = [l.strip() for l in open(wl) if l.strip()]
    await asyncio.gather(*(one(w) for w in words))

if __name__ == '__main__':
    asyncio.run(main(*sys.argv[1:]))
```

Der Hash-Vergleich versagt bei dynamischen 404-Seiten, die den angefragten Pfad im Body spiegeln — dann auf Längen-Buckets mit Toleranz ausweichen. `rps` ist Pflichtparameter, nicht Empfehlung. Erlaubt die Policy kein Fuzzing, entfällt diese Stufe ganz; dann werden nur beobachtete Pfade geprüft.

## 6 — Was hier nicht geht

| Fehlt | Konsequenz |
|---|---|
| `dig`/`dnspython` | CNAME, NS, TXT unsichtbar → keine saubere Takeover-Erkennung |
| Wordlisten | Fuzzing-Liste muss aus eigenem Recon erzeugt werden |
| `nuclei` | kein Template-Scan; für XSS kein Verlust, blindes Spray ist verboten |
| Python-Modul `playwright` | Browser ausschließlich über Node ansteuern: `NODE_PATH=$(npm root -g) node capture.js` |
| `httpx`, `aiohttp`, `dnspython`, `bs4` (python) | Stdlib bevorzugen: `urllib`, `socket`, `asyncio`, `concurrent.futures`. `requests` ist vorhanden, wird aber nicht gebraucht |
