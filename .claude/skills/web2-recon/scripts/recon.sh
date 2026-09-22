#!/usr/bin/env bash
# recon.sh — Recon-Pipeline mit Werkzeug-Erkennung.
#
# Nutzung:  recon.sh <root-domain> [--scope-ok] [-o <outdir>]
#
# Ohne --scope-ok laufen nur passive Stufen (CT-Logs, Archiv, DNS). Jede Stufe, die
# das Target selbst anfasst, verlangt die bestaetigte Scope-Pruefung — siehe
# references/pipeline.md Abschnitt 0.
#
# Ergebnisse:  evidence/<root-domain>/recon/   (Konvention des Hunt-Prompts)
# Env:  RECON_UA (Default denibkv-hackerone-research; Programm-Vorgabe hat Vorrang)
#       RECON_PAR (Parallelitaet, Default 5)   RECON_WORDLIST (DNS-Bruteforce, optional)

set -euo pipefail

UA="${RECON_UA:-denibkv-hackerone-research}"
PAR="${RECON_PAR:-5}"
WORDLIST="${RECON_WORDLIST:-}"
APEX=""; OUT=""; SCOPE_OK=0; WARNINGS=0

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; }

info() { printf '\033[1m[*]\033[0m %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; WARNINGS=$((WARNINGS+1)); }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Quellen-Ausfall ist ein Zustand, kein Ergebnis: laut melden, weitermachen.
ausfall() { warn "QUELLE AUSGEFALLEN: $1 — kein Ergebnis heisst hier NICHT 'nichts gefunden'. Zweite Quelle ziehen oder in einer Umgebung mit Egress wiederholen."; }

while [ $# -gt 0 ]; do
  case "$1" in
    --scope-ok) SCOPE_OK=1 ;;
    -o|--out)   shift; OUT="${1:-}" ;;
    -h|--help)  usage; exit 0 ;;
    -*)         die "Unbekannte Option: $1" ;;
    *)          if [ -z "$APEX" ]; then APEX="$1"; else die "Zu viele Argumente: $1"; fi ;;
  esac
  shift
done

[ -n "$APEX" ] || { usage; exit 1; }
APEX="$(printf '%s' "$APEX" | tr 'A-Z' 'a-z' | sed -e 's#^https\{0,1\}://##' -e 's#/.*$##')"
case "$APEX" in
  *.*) : ;;
  *)   die "'$APEX' sieht nicht wie eine Root-Domain aus." ;;
esac

OUT="${OUT:-evidence/$APEX/recon}"
mkdir -p "$OUT/js" "$OUT/tools" "$OUT/src"
OUT="$(cd "$OUT" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CURL=(curl -sS --compressed --connect-timeout 6 --max-time 60 -A "$UA")

# ---------------------------------------------------------------- Stufe 0: Werkzeuge + Scope
info "Werkzeug-Erkennung"
: > "$OUT/00-werkzeuge.txt"
for t in curl python3 node npx jq openssl dig subfinder assetfinder dnsx httpx katana gau waybackurls ffuf nuclei prettier; do
  if have "$t"; then printf '%-14s vorhanden\n' "$t"; else printf '%-14s FEHLT\n' "$t"; fi
done | tee "$OUT/00-werkzeuge.txt"

have curl    || die "curl fehlt — ohne curl laeuft keine Stufe."
have python3 || warn "python3 fehlt — DNS-Bruteforce und JS-Analyse entfallen."
have jq      || warn "jq fehlt — CT- und Archiv-Auswertung entfaellt."

cat > "$OUT/00-scope-checkliste.md" <<SCOPEEOF
# Scope-Pruefung $APEX — vor dem ersten aktiven Request

Auf der Programmseite nachlesen. Was dort nicht steht, wird als offene Frage notiert, nicht geraten.

- [ ] In-Scope-Assets und Wildcards vollstaendig gelesen, Wildcards aufgeloest
- [ ] Out-of-Scope-Liste vollstaendig gelesen und hier woertlich eingetragen
- [ ] Automatisiertes Scannen/Fuzzing erlaubt? Rate-Limit? (falls nein: kein Fuzzing, sequenziell mit Delay)
- [ ] Geforderter Identifikations-Header / Kennzeichnung? (Programm-Vorgabe schlaegt den Default)
- [ ] Testaccount-Regeln: eigene Accounts erlaubt, Kennzeichnung gefordert, mind. 2 Konten vorhanden
- [ ] Erstattungsfaehige Varianten und Severity-Grundlage der Policy
- [ ] Bekannte / bereits gemeldete Issues, die Pfade ausschliessen

Verwendete Kennung dieses Laufs: User-Agent: $UA
Keine Programm-Vorgabe gefunden? Dann hier vermerken, damit die Annahme sichtbar bleibt: ____________
SCOPEEOF
ok "Scope-Checkliste: $OUT/00-scope-checkliste.md"

if [ "$SCOPE_OK" -eq 0 ]; then
  warn "Ohne --scope-ok laufen nur passive Stufen. Aktive Stufen (Host-Probing, Crawl) uebersprungen."
fi

# ---------------------------------------------------------------- Stufe 1: Subdomains (passiv)
stufe_subdomains() {
  info "Stufe 1 — Subdomains"
  local n=0
  if have subfinder; then
    subfinder -d "$APEX" -all -silent > "$TMP/subs-tool.txt" 2>/dev/null || ausfall "subfinder"
  fi
  if have assetfinder; then
    assetfinder --subs-only "$APEX" >> "$TMP/subs-tool.txt" 2>/dev/null || ausfall "assetfinder"
  fi
  # crt.sh laeuft immer mit: zweite unabhaengige Quelle. '%' MUSS als %25 kodiert sein.
  if have jq; then
    if "${CURL[@]}" --max-time 90 --retry 3 --retry-delay 5 \
         "https://crt.sh/?q=%25.${APEX}&output=json" -o "$TMP/crtsh.json" 2>"$TMP/crtsh.err"; then
      if jq -e 'type == "array"' "$TMP/crtsh.json" >/dev/null 2>&1; then
        jq -r '.[].name_value, .[].common_name' "$TMP/crtsh.json" 2>/dev/null \
          | tr 'A-Z' 'a-z' | sed 's/^\*\.//' \
          | grep -E '^[a-z0-9._-]+$' > "$TMP/subs-ct.txt" || true
        cp "$TMP/crtsh.json" "$OUT/01-crtsh.json"
      else
        ausfall "crt.sh (Antwort ist kein JSON-Array)"
      fi
    else
      ausfall "crt.sh ($(head -c 120 "$TMP/crtsh.err" 2>/dev/null || echo 'keine Verbindung'))"
    fi
  fi
  cat "$TMP/subs-tool.txt" "$TMP/subs-ct.txt" 2>/dev/null \
    | grep -E "(^|\.)${APEX//./\\.}$" | sort -u > "$OUT/01-subdomains.txt" || true
  n=$(wc -l < "$OUT/01-subdomains.txt" | tr -d ' ')
  if [ "$n" -eq 0 ]; then
    ausfall "keine Subdomain-Quelle lieferte Daten"
  else
    ok "Stufe 1: $n Subdomains -> $OUT/01-subdomains.txt"
  fi
}

# ---------------------------------------------------------------- Stufe 2: DNS (passiv)
stufe_dns() {
  info "Stufe 2 — Wildcard-Check und Aufloesung"
  have python3 || { warn "python3 fehlt — Stufe 2 uebersprungen."; return 0; }

  local wc
  wc="$(python3 - "$APEX" <<'PY' 2>/dev/null || echo 'DNS-FEHLER'
import socket, sys
apex = sys.argv[1]
try:
    ip = socket.getaddrinfo(f'zzq7x3-nonexistent.{apex}', None)[0][4][0]
    print(f'WILDCARD-VERDACHT ({ip})')
except socket.gaierror:
    print('NXDOMAIN (kein Wildcard)')
except Exception:
    print('DNS-FEHLER')
PY
)"
  printf 'Wildcard-Check %s: %s\n' "$APEX" "$wc" | tee "$OUT/02-wildcard.txt"
  case "$wc" in
    WILDCARD*) warn "Wildcard-DNS aktiv — Bruteforce-Treffer sind wertlos, Stufe uebersprungen." ; return 0 ;;
    DNS-FEHLER) ausfall "DNS-Aufloesung" ; return 0 ;;
  esac

  # Kandidatenliste: eigene Recon-Ergebnisse schlagen jede generische Wordlist.
  : > "$TMP/cand.txt"
  [ -s "$OUT/01-subdomains.txt" ] && sed "s/\.${APEX//./\\.}$//" "$OUT/01-subdomains.txt" >> "$TMP/cand.txt"
  if [ -n "$WORDLIST" ] && [ -r "$WORDLIST" ]; then
    cat "$WORDLIST" >> "$TMP/cand.txt"
  elif [ -n "$WORDLIST" ]; then
    warn "Wordlist '$WORDLIST' nicht lesbar — nur eigene Recon-Ergebnisse werden aufgeloest."
  fi
  sort -u "$TMP/cand.txt" | grep -Ev '^\s*$' > "$TMP/cand-u.txt" || true
  [ -s "$TMP/cand-u.txt" ] || { warn "Keine Kandidaten fuer die Aufloesung."; return 0; }

  python3 - "$TMP/cand-u.txt" "$APEX" <<'PY' > "$OUT/02-resolved.tsv" 2>/dev/null || ausfall "DNS-Aufloesung"
import socket, sys, concurrent.futures as cf
wl, apex = sys.argv[1], sys.argv[2]
socket.setdefaulttimeout(3)

def r(name):
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        return name, sorted({i[4][0] for i in infos})
    except (socket.gaierror, OSError):
        return None

names = []
for line in open(wl):
    w = line.strip()
    if not w or w.startswith('#'):
        continue
    names.append(w if w.endswith(apex) else f'{w}.{apex}')
with cf.ThreadPoolExecutor(max_workers=50) as ex:
    for res in ex.map(r, sorted(set(names))):
        if res:
            print(f'{res[0]}\t{",".join(res[1])}')
PY
  ok "Stufe 2: $(wc -l < "$OUT/02-resolved.tsv" | tr -d ' ') aufgeloeste Hosts -> $OUT/02-resolved.tsv"
  printf '# getaddrinfo liefert nur A/AAAA — CNAME, NS und TXT bleiben unsichtbar.\n' >> "$OUT/02-resolved.tsv"
}

# ---------------------------------------------------------------- Stufe 3: Live-Hosts (aktiv)
probe_host() {
  local h="$1" out code eff srv csp ttl scheme
  for scheme in https http; do
    out=$(curl -sS -o "$TMP/body.$$" -D "$TMP/hdr.$$" \
          --max-time 12 --connect-timeout 6 -L --max-redirs 3 -A "$RECON_UA_EXPORT" \
          -w '%{http_code}\t%{url_effective}' "$scheme://$h/" 2>/dev/null) || continue
    code=$(printf '%s' "$out" | cut -f1); eff=$(printf '%s' "$out" | cut -f2)
    [ "$code" = "000" ] && continue
    srv=$(grep -im1 '^server:'                  "$TMP/hdr.$$" | tr -d '\r' | cut -d' ' -f2- || true)
    csp=$(grep -im1 '^content-security-policy:' "$TMP/hdr.$$" | tr -d '\r' | cut -c1-200 || true)
    ttl=$(tr -d '\n' < "$TMP/body.$$" | grep -oiP '<title[^>]*>\K.*?(?=</title>)' | cut -c1-80 || true)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$h" "$code" "${srv:--}" "${eff:--}" "${ttl:--}" "${csp:--}"
    rm -f "$TMP/body.$$" "$TMP/hdr.$$"
    return 0
  done
  rm -f "$TMP/body.$$" "$TMP/hdr.$$"
  return 0
}

stufe_hosts() {
  info "Stufe 3 — Live-Hosts (aktiv)"
  [ -s "$OUT/01-subdomains.txt" ] || { warn "Keine Hostliste — Stufe 3 uebersprungen."; return 0; }
  if have httpx; then
    httpx -l "$OUT/01-subdomains.txt" -silent -status-code -title -web-server \
          -include-response-header -json -o "$OUT/03-hosts.json" 2>/dev/null \
      || ausfall "httpx"
    ok "Stufe 3: $OUT/03-hosts.json"
    return 0
  fi
  export RECON_UA_EXPORT="$UA" TMP
  export -f probe_host
  printf 'host\tstatus\tserver\tredirect\ttitel\tcsp\n' > "$OUT/03-hosts.tsv"
  # -P begrenzt die Parallelitaet: Programmregeln zu Automatisierung haben Vorrang.
  xargs -P "$PAR" -I{} bash -c 'probe_host "$@"' _ {} < "$OUT/01-subdomains.txt" \
    >> "$OUT/03-hosts.tsv" 2>/dev/null || true
  local n; n=$(( $(wc -l < "$OUT/03-hosts.tsv" | tr -d ' ') - 1 ))
  [ "$n" -gt 0 ] || ausfall "kein Host antwortete (Status 000 = tot oder Egress geblockt)"
  ok "Stufe 3: $n Live-Hosts -> $OUT/03-hosts.tsv"
  printf '# CSP stammt vom ERSTEN Hop; fuer das Ziel-CSP zweiter Aufruf gegen die Redirect-URL ohne -L.\n' >> "$OUT/03-hosts.tsv"
}

# ---------------------------------------------------------------- Stufe 4: URLs/Historie (passiv)
stufe_urls() {
  info "Stufe 4 — URLs und Historie"
  if have gau; then
    gau "$APEX" > "$OUT/04-urls-all.txt" 2>/dev/null || ausfall "gau"
  elif have waybackurls; then
    waybackurls "$APEX" > "$OUT/04-urls-all.txt" 2>/dev/null || ausfall "waybackurls"
  elif have jq; then
    if "${CURL[@]}" --max-time 120 \
        "https://web.archive.org/cdx/search/cdx?url=${APEX}&matchType=domain&output=json&fl=original,mimetype,statuscode,timestamp&collapse=urlkey&filter=statuscode:200&limit=50000" \
        -o "$TMP/cdx.json" 2>"$TMP/cdx.err"; then
      if jq -e 'type == "array"' "$TMP/cdx.json" >/dev/null 2>&1; then
        cp "$TMP/cdx.json" "$OUT/04-cdx.json"
        # Kopfzeile ist das ERSTE Array-Element und muss mit .[1:] abgeworfen werden.
        jq -r '.[1:][] | .[0]' "$TMP/cdx.json" | sort -u > "$OUT/04-urls-all.txt" || true
        jq -r '.[1:][] | select(.[1]|test("javascript")) | .[0]' "$TMP/cdx.json" | sort -u > "$OUT/04-urls-js.txt" || true
      else
        ausfall "Wayback CDX (Antwort ist kein JSON-Array)"
      fi
    else
      ausfall "Wayback CDX ($(head -c 120 "$TMP/cdx.err" 2>/dev/null || echo 'keine Verbindung'))"
    fi
  fi
  [ -f "$OUT/04-urls-all.txt" ] || : > "$OUT/04-urls-all.txt"
  grep '?' "$OUT/04-urls-all.txt" | sort -u > "$OUT/04-urls-param.txt" || true

  if have python3 && [ -s "$OUT/04-urls-param.txt" ]; then
    python3 - "$OUT/04-urls-param.txt" <<'PY' > "$OUT/04-parameter.txt" 2>/dev/null || true
import sys, collections
from urllib.parse import urlsplit, parse_qsl
c = collections.Counter()
for line in open(sys.argv[1], errors='replace'):
    for k, _ in parse_qsl(urlsplit(line.strip()).query, keep_blank_values=True):
        c[k] += 1
for k, n in c.most_common():
    print(f'{n}\t{k}')
PY
  fi
  local n; n=$(wc -l < "$OUT/04-urls-param.txt" | tr -d ' ')
  if [ "$n" -eq 0 ]; then ausfall "keine URL-Quelle lieferte Daten"
  else ok "Stufe 4: $n parametrisierte URLs (= Reflection-Kandidaten) -> $OUT/04-urls-param.txt"; fi
}

# ---------------------------------------------------------------- Stufe 5: Crawl (aktiv)
schreibe_capture_js() {
  cat > "$OUT/tools/capture.js" <<'JSEOF'
// Nutzung: NODE_PATH=$(npm root -g) node capture.js <url> <outdir>
const { chromium } = require('playwright');
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [url, outDir = 'recon-out'] = process.argv.slice(2);
const UA = process.env.RECON_UA || 'denibkv-hackerone-research';
fs.mkdirSync(path.join(outDir, 'js'), { recursive: true });

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ userAgent: UA, ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const assets = [], endpoints = [], headerLog = [];

  page.on('response', async (res) => {
    const req = res.request(), u = res.url(), h = res.headers();
    const ct = (h['content-type'] || '').toLowerCase();
    const isJS = /\.m?js(\?|$)/i.test(u) || ct.includes('javascript') || ct.includes('ecmascript');
    headerLog.push({ url: u, status: res.status(), type: req.resourceType(),
      csp: h['content-security-policy'] || null,
      cspRO: h['content-security-policy-report-only'] || null,
      xfo: h['x-frame-options'] || null, cto: h['x-content-type-options'] || null,
      server: h['server'] || null, setCookie: h['set-cookie'] ? '(vorhanden)' : null,
      location: h['location'] || null, cors: h['access-control-allow-origin'] || null });
    if (['xhr', 'fetch', 'websocket'].includes(req.resourceType()))
      endpoints.push({ method: req.method(), url: u, status: res.status() });
    if (!isJS) return;
    try {                                   // wirft bei Redirects und Cache-Responses
      const body = await res.body();
      const name = crypto.createHash('sha1').update(u).digest('hex').slice(0, 12)
                 + '_' + (u.split('/').pop().split('?')[0] || 'asset');
      fs.writeFileSync(path.join(outDir, 'js', name), body);
      const sm = body.toString('utf8').match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
      assets.push({ url: u, bytes: body.length, file: name, sourceMappingURL: sm ? sm[1] : null });
    } catch (e) { assets.push({ url: u, error: String(e.message) }); }
  });

  await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 });
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)).catch(() => {});
  await page.waitForTimeout(3000);          // Lazy-Chunks anstossen
  const metaCSP = await page.$$eval('meta[http-equiv="Content-Security-Policy" i]',
                                    els => els.map(e => e.getAttribute('content'))).catch(() => []);
  const inline = await page.$$eval('script:not([src])', els => els.map(e => e.textContent.slice(0, 2000))).catch(() => []);
  for (const [f, d] of [['05-assets', assets], ['05-headers', headerLog], ['05-endpoints', endpoints],
                        ['05-inline-scripts', inline], ['05-meta-csp', metaCSP]])
    fs.writeFileSync(path.join(outDir, `${f}.json`), JSON.stringify(d, null, 2));
  console.log(`JS-Assets: ${assets.length} | Responses: ${headerLog.length} | ` +
              `XHR/fetch: ${endpoints.length} | meta-CSP: ${metaCSP.length}`);
  await browser.close();
})();
JSEOF
}

stufe_crawl() {
  info "Stufe 5 — Crawl und JS-Assets (aktiv)"
  if have katana; then
    katana -u "https://$APEX" -jc -kf all -silent > "$OUT/05-katana.txt" 2>/dev/null || ausfall "katana"
  fi
  have node || { warn "node fehlt — Browser-Crawl entfaellt."; return 0; }
  schreibe_capture_js
  local np; np="$(npm root -g 2>/dev/null || true)"
  if ! NODE_PATH="$np" node "$OUT/tools/capture.js" "https://$APEX/" "$OUT" 2>"$TMP/crawl.err"; then
    ausfall "Browser-Crawl ($(head -c 160 "$TMP/crawl.err" 2>/dev/null || echo 'siehe Log'))"
    return 0
  fi
  ok "Stufe 5: Crawl-Artefakte in $OUT (05-*.json), Bundles in $OUT/js/"
}

# ---------------------------------------------------------------- Stufe 6: JS-Analyse
schreibe_unmap_py() {
  cat > "$OUT/tools/unmap.py" <<'PYEOF'
#!/usr/bin/env python3
"""Schreibt sourcesContent einer .map in einen Verzeichnisbaum. Nutzung: unmap.py <map> <outdir>"""
import json, sys, re
from pathlib import Path

def safe_rel(src: str, i: int) -> Path:
    s = re.sub(r'^[a-zA-Z0-9.+-]+://', '', src)          # webpack://, file://, http(s)://
    s = s.replace('\\', '/')
    parts = [p for p in s.split('/') if p not in ('', '.', '..')]
    parts = [re.sub(r'[^A-Za-z0-9._\-]', '_', p) for p in parts]
    return Path(*parts) if parts else Path(f'source_{i}.js')

def main(mapfile, outdir):
    data = json.loads(Path(mapfile).read_text(encoding='utf-8', errors='replace'))
    sources, contents = data.get('sources') or [], data.get('sourcesContent') or []
    root = Path(outdir).resolve(); n = 0
    if not contents:
        print('sourcesContent fehlt - nur Pfadliste verwertbar:')
        for s in sources: print(' ', s)
        return
    for i, src in enumerate(sources):
        body = contents[i] if i < len(contents) else None
        if body is None: continue
        dest = (root / safe_rel(src, i)).resolve()
        if not str(dest).startswith(str(root)):          # Traversal-Guard: Map ist fremder Input
            dest = root / f'unsafe_{i}.js'
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding='utf-8'); n += 1
    print(f'{n}/{len(sources)} Quellen -> {root}')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
PYEOF
}

stufe_js() {
  info "Stufe 6 — Source Maps, Endpunkte, Secrets, Routen"
  have python3 || { warn "python3 fehlt — Stufe 6 uebersprungen."; return 0; }
  local anzahl; anzahl=$(find "$OUT/js" -type f 2>/dev/null | wc -l | tr -d ' ')
  if [ "$anzahl" -eq 0 ]; then
    warn "Keine Bundles in $OUT/js — Stufe 5 lieferte nichts. Bundles manuell ablegen und erneut starten."
    return 0
  fi
  schreibe_unmap_py

  # Source Maps: nur ziehen, wenn Scope bestaetigt ist (das ist ein Request ans Target).
  if [ "$SCOPE_OK" -eq 1 ] && [ -s "$OUT/05-assets.json" ] && have jq; then
    local u smurl base
    while IFS= read -r u; do
      [ -n "$u" ] || continue
      smurl="$(jq -r --arg u "$u" '.[] | select(.url==$u) | .sourceMappingURL // empty' "$OUT/05-assets.json" | head -1)"
      [ -n "$smurl" ] || continue
      case "$smurl" in
        data:*) continue ;;
        http*)  : ;;
        /*)     smurl="https://${APEX}${smurl}" ;;
        *)      base="${u%/*}"; smurl="${base}/${smurl}" ;;
      esac
      if "${CURL[@]}" "$smurl" -o "$TMP/map.json" 2>/dev/null; then
        python3 "$OUT/tools/unmap.py" "$TMP/map.json" "$OUT/src" 2>/dev/null || warn "Map nicht verwertbar: $smurl"
      else
        ausfall "Source Map $smurl"
      fi
    done < <(jq -r '.[].url // empty' "$OUT/05-assets.json" 2>/dev/null || true)
  fi

  python3 - "$OUT" <<'PYEOF' > "$OUT/06-analyse.md" 2>/dev/null || warn "JS-Analyse fehlgeschlagen."
import re, sys
from pathlib import Path

out = Path(sys.argv[1])
files = [p for p in list((out/'js').rglob('*')) + list((out/'src').rglob('*')) if p.is_file()]

ENDPOINTS = [
    ('quoted-path',  r"""['"`](/[A-Za-z0-9_\-./{}:$]{2,120})['"`]"""),
    ('abs-url',      r"""['"`](https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./{}:$?=&%]*)?)['"`]"""),
    ('ws-url',       r"""['"`](wss?://[A-Za-z0-9._\-]+(?:/[^'"`]*)?)['"`]"""),
    ('fetch',        r"""\bfetch\s*\(\s*['"`]([^'"`]+)"""),
    ('baseURL',      r"""\bbaseURL\s*[:=]\s*['"`]([^'"`]+)"""),
    # Kein sprechender Bezeichner: im minifizierten Bundle heisst der Client a/e/t.
    ('http-methode', r"""\b[A-Za-z_$][\w$]*\s*\.\s*(?:get|post|put|patch|delete|request|head)\s*\(\s*['"`]([^'"`]+)"""),
]
SECRETS = [
    ('google-api-key', r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ('aws-key-id',     r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
    ('github-token',   r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b"),
    ('stripe-key',     r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b"),
    ('jwt',            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ('zuweisung',      r"""(?i)\b(?:api[_-]?key|secret|passwd|password|token|auth)\s*[:=]\s*['"][A-Za-z0-9_\-!@#$%^&*]{12,}['"]"""),
]
ROUTES = [
    ('react-router', r"""\bpath\s*:\s*['"`]([^'"`]+)['"`]"""),
    ('abs-path',     r"""\bpath\s*[:=]\s*['"`](/[^'"`]*)['"`]"""),
    ('jsx-route',    r"""createElement\(\s*[A-Za-z_$][\w$]*\s*,\s*\{[^}]*?\bpath\s*:\s*['"`]([^'"`]+)"""),
    ('vue-router',   r"""\{\s*path\s*:\s*['"`]([^'"`]+)['"`]\s*,\s*(?:name|component)\s*:"""),
]

def sammeln(muster):
    treffer = {}
    for p in files:
        try:
            txt = p.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for name, rx in muster:
            for m in re.finditer(rx, txt):
                wert = m.group(1) if m.groups() else m.group(0)
                treffer.setdefault((name, wert), set()).add(p.name)
    return treffer

def block(titel, treffer, limit=400, maskieren=False):
    print(f'\n## {titel} ({len(treffer)})\n')
    if not treffer:
        print('_keine Treffer_')
        return
    print('| Muster | Wert | Datei |')
    print('|---|---|---|')
    for (name, wert), dateien in sorted(treffer.items())[:limit]:
        w = (wert[:18] + '…' + wert[-4:]) if maskieren and len(wert) > 24 else wert[:110]
        w = w.replace('|', '\\|')
        print(f'| {name} | `{w}` | {sorted(dateien)[0]} |')
    if len(treffer) > limit:
        print(f'\n_{len(treffer) - limit} weitere Treffer abgeschnitten._')

print(f'# JS-Analyse — {len(files)} Dateien\n')
print('Jeder Treffer ist ein Kandidat, kein Finding. Endpunkte am Target verifizieren;')
print('Secret-Kandidaten nur im Rahmen der Programmregeln bewerten, niemals fremde Credentials benutzen.')
block('Endpunkte', sammeln(ENDPOINTS))
block('Routen (Parameter-Segmente zuerst pruefen)', sammeln(ROUTES))
block('Secret-Kandidaten', sammeln(SECRETS), limit=100, maskieren=True)

sm = [p.name for p in files if 'sourceMappingURL' in p.read_text(encoding='utf-8', errors='replace')[:200000]]
print(f'\n## sourceMappingURL gefunden in {len(sm)} Datei(en)\n')
for n in sorted(set(sm))[:50]:
    print(f'- {n}')
PYEOF
  ok "Stufe 6: $OUT/06-analyse.md"
  [ -n "$(find "$OUT/src" -type f 2>/dev/null | head -1)" ] && ok "Rekonstruierte Quellen: $OUT/src/"
  return 0
}

# ---------------------------------------------------------------- Stufe 7: Uebergabe
stufe_uebergabe() {
  cat > "$OUT/07-uebergabe.md" <<UEBEOF
# Recon-Uebergabe $APEX

Lauf beendet: $(date '+%Y-%m-%d %H:%M') | Kennung: $UA | Warnungen: $WARNINGS

## Artefakte

| Datei | Inhalt |
|---|---|
| 00-werkzeuge.txt | welche Werkzeuge dieser Lauf wirklich hatte |
| 00-scope-checkliste.md | Scope-Fragen, offen bis auf der Programmseite geprueft |
| 01-subdomains.txt | Subdomains, Quelle: CT-Log und/oder Tool |
| 02-wildcard.txt / 02-resolved.tsv | Wildcard-Befund, aufgeloeste Hosts (nur A/AAAA) |
| 03-hosts.tsv bzw. 03-hosts.json | Live-Hosts: Status, Server, Redirect, Titel, CSP |
| 04-urls-param.txt / 04-parameter.txt | parametrisierte URLs und Parameter-Namen = Reflection-Kandidaten |
| 05-*.json | Crawl: Assets, Header, XHR/fetch-Ziele, Inline-Scripts, Meta-CSP |
| 06-analyse.md | Endpunkte, Routen, Secret-Kandidaten aus Bundles und Quellen |
| js/ , src/ | gesicherte Bundles, rekonstruierte Source-Map-Quellen |

## Naechste Schritte

1. CSP aus 03/05 (Header **und** Meta) auswerten — entscheidet, welche Payload-Klassen ueberhaupt Sinn ergeben.
2. Bundles lesbar machen: \`npx --no-install prettier --parser babel js/<datei>\`, dann Sink-Arbeit mit **dom-sink-hooker**.
3. Reflection-Sonde auf 04-parameter.txt: Marker \`xss7q3z\` je Parameter, Kontext des Treffers bestimmen.
4. Blocker beobachtet? → **waf-sanitizer-playbook**: references/bypass-map.md + references/payload-ladders.md.
5. Upload-Flaechen aus dem Crawl → references/upload-vektoren.md.
6. Zustandsaendernder Endpunkt, der einen Stored-Sink fuettert → optional **csrf-hunter** fuer die Chain.

Recon liefert Angriffsflaeche, keine Findings. Nichts aus dieser Ablage ist bewertet.
UEBEOF
  ok "Uebergabe: $OUT/07-uebergabe.md"
}

# ---------------------------------------------------------------- Ablauf
stufe_subdomains || warn "Stufe 1 abgebrochen."
stufe_dns        || warn "Stufe 2 abgebrochen."
if [ "$SCOPE_OK" -eq 1 ]; then
  stufe_hosts    || warn "Stufe 3 abgebrochen."
else
  info "Stufe 3 uebersprungen (aktiv, braucht --scope-ok)"
fi
stufe_urls       || warn "Stufe 4 abgebrochen."
if [ "$SCOPE_OK" -eq 1 ]; then
  stufe_crawl    || warn "Stufe 5 abgebrochen."
else
  info "Stufe 5 uebersprungen (aktiv, braucht --scope-ok)"
fi
stufe_js         || warn "Stufe 6 abgebrochen."
stufe_uebergabe  || warn "Stufe 7 abgebrochen."

echo
if [ "$WARNINGS" -gt 0 ]; then
  info "Fertig mit $WARNINGS Warnung(en) — jede ausgefallene Quelle ist eine Luecke im Inventar, kein leeres Ergebnis."
else
  info "Fertig ohne Warnungen."
fi
info "Ablage: $OUT"
