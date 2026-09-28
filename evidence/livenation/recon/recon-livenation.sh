#!/usr/bin/env bash
# Live Nation (HackerOne: live_nation) — Recon-Runner für unauthentifiziertes DOM-XSS.
#
# Auf einer Maschine MIT Egress ausführen. Der Analyse-Container hat keinen.
#
# Zwei Programm-Regeln sind hier hart verdrahtet:
#   1. Nur die 22 gelisteten Hosts. Keine Wildcards im Scope -> keine
#      Subdomain-Enumeration. Was nicht in hosts.txt steht, wird nicht angefasst.
#   2. "No automated scanning on checkout/ payment flows." -> DENY unten schließt
#      diese Pfade aus jedem Crawl aus. Nicht lockern.
#
# Vor dem ersten Request: https://hackerone.com/live_nation lesen. Rate-Limits,
# erlaubte Testarten und Safe Harbour stehen dort, nicht im Scope-Datensatz.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/out}"
HOSTS="${HOSTS:-$HERE/../../../scope/live_nation/domains.txt}"
# Pfad zu sink_scan.py aus der xss-sink-recon-Skill
SINK_SCAN="${SINK_SCAN:-}"
UA="${UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36}"
RATE="${RATE:-5}"          # Requests/s Obergrenze für Crawler
DEPTH="${DEPTH:-3}"

# Regel 2: Checkout/Payment aus jeder Automatisierung ausschließen.
DENY='(checkout|payment|purchase|billing|cart|basket|order/|/pay|creditcard|card-entry|3ds|apple-?pay|google-?pay|paypal)'

mkdir -p "$OUT"/{headers,js,map,crawl,scan}
have() { command -v "$1" >/dev/null 2>&1; }
log() { printf '\n\033[1m[*] %s\033[0m\n' "$*"; }

[ -s "$HOSTS" ] || { echo "FEHLT: $HOSTS"; exit 1; }
log "Scope: $(wc -l < "$HOSTS") Hosts, fix, keine Wildcards"

# ---------------------------------------------------------------- 1. Schutzschichten
# Was liefert jeder Origin, und was blockt dort CSP? Das entscheidet später, ob ein
# gefundener Sink überhaupt zu Script-Ausführung führt.
log "Phase 1 — Header- und CSP-Inventar"
if have httpx; then
  httpx -l "$HOSTS" -silent -sc -title -tech-detect -server -location \
        -rl "$RATE" -H "User-Agent: $UA" \
        -json -o "$OUT/headers/httpx.json"
  # CSP separat, httpx -tech-detect zeigt sie nicht
  while read -r h; do
    [ -z "$h" ] && continue
    printf '=== %s ===\n' "$h"
    curl -sS -D - -o /dev/null --max-time 25 -A "$UA" "https://$h/" 2>&1 \
      | grep -iE '^(HTTP/|location|server|content-security-policy|x-frame-options|set-cookie|report-to)' \
      | cut -c1-400
    sleep 1
  done < "$HOSTS" | tee "$OUT/headers/csp.txt" >/dev/null
else
  log "kein httpx — curl-Fallback"
  while read -r h; do
    [ -z "$h" ] && continue
    printf '=== %s ===\n' "$h"
    curl -sS -D - -o /dev/null --max-time 25 -A "$UA" "https://$h/" 2>&1 \
      | grep -iE '^(HTTP/|location|server|content-security-policy|x-frame-options|set-cookie)' \
      | cut -c1-400
    sleep 1
  done < "$HOSTS" | tee "$OUT/headers/csp.txt" >/dev/null
fi
grep -ic 'content-security-policy' "$OUT/headers/csp.txt" \
  | xargs -I{} echo "    Hosts mit CSP-Header: {} / $(wc -l < "$HOSTS")"

# ---------------------------------------------------------------- 2. URLs + Parameter
log "Phase 2 — URL-Oberfläche (historisch + Crawl), Checkout ausgeschlossen"
if have gau; then
  gau --threads 4 --subs=false < "$HOSTS" 2>/dev/null \
    | grep -vEi "$DENY" | sort -u > "$OUT/crawl/historic.txt"
  echo "    gau: $(wc -l < "$OUT/crawl/historic.txt") URLs"
fi
if have katana; then
  sed 's|^|https://|' "$HOSTS" > "$OUT/crawl/seeds.txt"
  katana -list "$OUT/crawl/seeds.txt" -d "$DEPTH" -jc -kf all -silent \
         -rl "$RATE" -H "User-Agent: $UA" \
         -cos "$DENY" \
         -o "$OUT/crawl/katana.txt"
  echo "    katana: $(wc -l < "$OUT/crawl/katana.txt" 2>/dev/null || echo 0) URLs"
fi
cat "$OUT/crawl/"historic.txt "$OUT/crawl/"katana.txt 2>/dev/null \
  | grep -vEi "$DENY" | sort -u > "$OUT/crawl/all.txt"

# Reflection-Kandidaten: die Parameternamen, die erfahrungsgemäß in Sinks landen.
grep -oE '[?&][A-Za-z0-9_.\[\]-]+=' "$OUT/crawl/all.txt" 2>/dev/null \
  | tr -d '?&=' | sort | uniq -c | sort -rn > "$OUT/crawl/params-by-frequency.txt"
grep -iE '[?&](url|uri|next|redirect|redirect_uri|return|returnUrl|returnTo|continue|dest|destination|target|goto|link|href|callback|cb|jsonp|q|query|search|term|keyword|msg|message|error|err|title|name|desc|ref|referrer|lang|locale|theme|template|view|page|src|data|html|content|embed)=' \
  "$OUT/crawl/all.txt" 2>/dev/null | sort -u > "$OUT/crawl/sink-candidate-urls.txt"
echo "    Parameter-URLs mit Sink-Verdacht: $(wc -l < "$OUT/crawl/sink-candidate-urls.txt" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------- 3. JS + Source-Maps
log "Phase 3 — JS-Bundles holen, Source-Maps rekonstruieren"
grep -oiE 'https?://[^"'"'"' )]+\.m?js(\?[^"'"'"' )]*)?' "$OUT/crawl/all.txt" 2>/dev/null \
  | sed 's/[?#].*$//' | sort -u > "$OUT/js/urls.txt"
# Auch die Startseiten selbst nach <script src> absuchen — der Crawl verpasst
# inline injizierte Bundles.
while read -r h; do
  [ -z "$h" ] && continue
  curl -sS --max-time 25 -A "$UA" "https://$h/" 2>/dev/null \
    | grep -oiE 'src="[^"]+\.m?js[^"]*"' | sed 's/^src="//;s/"$//;s/[?#].*$//' \
    | sed "s|^/|https://$h/|" 
  sleep 1
done < "$HOSTS" | grep -E '^https?://' | sort -u >> "$OUT/js/urls.txt"
sort -u -o "$OUT/js/urls.txt" "$OUT/js/urls.txt"
echo "    JS-URLs: $(wc -l < "$OUT/js/urls.txt")"

while read -r u; do
  [ -z "$u" ] && continue
  n="$(printf '%s' "$u" | sha1sum | cut -c1-12)"
  curl -sS --max-time 30 -A "$UA" "$u" -o "$OUT/js/$n.js" 2>/dev/null
  printf '%s  %s\n' "$n" "$u" >> "$OUT/js/index.txt"
  # Source-Map: der größte Qualitätssprung dieser Phase. Echte Variablennamen
  # verwandeln eine Vermutung über Erreichbarkeit in etwas Lesbares.
  m="$(grep -oE '//[#@] *sourceMappingURL=[^ */]+' "$OUT/js/$n.js" 2>/dev/null | tail -1 | sed 's/.*=//')"
  if [ -n "$m" ] && [ "${m#data:}" = "$m" ]; then
    curl -sS --max-time 30 -A "$UA" "$(dirname "$u")/$m" -o "$OUT/map/$n.map" 2>/dev/null
  fi
  sleep 0.2
done < "$OUT/js/urls.txt"

if have js-beautify; then js-beautify -r "$OUT/js/"*.js 2>/dev/null
elif have npx; then npx --yes js-beautify -r "$OUT/js/"*.js 2>/dev/null; fi

python3 - "$OUT/map" "$OUT/js-src" <<'PY'
import sys, json, pathlib
mapdir, outdir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
n = 0
for mp in mapdir.glob("*.map"):
    try: d = json.loads(mp.read_text(encoding="utf-8", errors="replace"))
    except Exception: continue
    for src, content in zip(d.get("sources") or [], d.get("sourcesContent") or []):
        if not content: continue
        rel = str(src).replace("webpack://", "").replace("../", "").lstrip("./ /")
        if not rel or rel.endswith("/"): continue
        p = outdir / mp.stem / rel
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8"); n += 1
        except Exception: pass
print(f"    Source-Map: {n} Originaldateien rekonstruiert -> {outdir}")
PY

# ---------------------------------------------------------------- 4. Sink-Scan
log "Phase 4 — Sink-Scan"
if [ -n "$SINK_SCAN" ] && [ -f "$SINK_SCAN" ]; then
  for t in "$OUT/js-src" "$OUT/js"; do
    [ -d "$t" ] || continue
    python3 "$SINK_SCAN" "$t" --out "$OUT/scan/$(basename "$t")" --format both --min-score 20
  done
else
  echo "    SINK_SCAN nicht gesetzt — grep-Fallback"
  grep -rnE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|\bv-html\b|bypassSecurityTrust|\beval\(|new Function\(|setTimeout\([^,)]*["'"'"']|location\.(href|assign|replace)|srcdoc|\$\(' \
    "$OUT/js-src" "$OUT/js" 2>/dev/null > "$OUT/scan/grep-sinks.txt"
  echo "    rohe Sink-Treffer: $(wc -l < "$OUT/scan/grep-sinks.txt")"
fi

# postMessage-Handler ohne Origin-Prüfung: eigene Klasse, unauthentifiziert
# erreichbar sobald der Origin framebar ist (X-Frame-Options aus Phase 1 prüfen).
grep -rnE 'addEventListener\(\s*["'"'"']message["'"'"']' "$OUT/js-src" "$OUT/js" 2>/dev/null \
  > "$OUT/scan/postmessage-handlers.txt"
echo "    postMessage-Handler: $(wc -l < "$OUT/scan/postmessage-handlers.txt")"

# Regel 1 gegenprüfen: hat irgendwas einen Host außerhalb der 22 berührt?
log "Scope-Selbstkontrolle"
grep -ohE 'https?://[^/"'"'"' ]+' "$OUT/crawl/all.txt" "$OUT/js/urls.txt" 2>/dev/null \
  | sed 's|https\?://||;s|:.*||' | sort -u > "$OUT/touched-hosts.txt"
comm -23 "$OUT/touched-hosts.txt" <(sort "$HOSTS") > "$OUT/touched-out-of-scope.txt"
if [ -s "$OUT/touched-out-of-scope.txt" ]; then
  echo "    !! $(wc -l < "$OUT/touched-out-of-scope.txt") Hosts außerhalb der Scope-Liste in den Ergebnissen."
  echo "       Das sind Drittanbieter-Referenzen (CDNs, Analytics). NICHT testen."
  head -15 "$OUT/touched-out-of-scope.txt" | sed 's/^/       /'
fi

log "Fertig. Ergebnisse: $OUT"
cat <<'NEXT'
    Reihenfolge fürs Weiterlesen:
      headers/csp.txt                  -> wo blockt CSP, wo nicht; wer ist framebar
      crawl/sink-candidate-urls.txt    -> Parameter die in Sinks landen können
      scan/js-src.md                   -> Sink-Kandidaten aus Original-Quellen (wertvollste)
      scan/postmessage-handlers.txt    -> jeden auf event.origin-Prüfung lesen
    Live-Bestätigung dann mit dom-sink-hooker im Browser, nicht durch Weiterlesen.
NEXT
