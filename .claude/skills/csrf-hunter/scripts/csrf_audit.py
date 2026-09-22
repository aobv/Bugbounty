#!/usr/bin/env python3
"""
csrf_audit.py — Endpunkt-Inventur für CSRF-Jagd aus Burp-XML- oder HAR-Export.

Liest einen Export (Burp "Save items" XML, base64-Dekodierung inklusive, oder
Browser/Burp HAR) und listet zustandsändernde Kandidaten mit CSRF-relevanten
Signalen: Token vorhanden?, SameSite-Attribute der gesetzten Cookies,
Simple-Request-Eignung (kein Preflight nötig?), Origin/Referer-Spuren.

Nur auf Daten autorisierte Bug-Bounty-Targets anwenden.

Aufruf:
    python3 csrf_audit.py <export.xml|export.har> [--host target.example]

Ausgabe: Tabelle auf stdout + Markdown-Report <datei>.csrf-report.md
"""

import argparse
import base64
import json
import re
import sys
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qsl

STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SIMPLE_CT = {
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
}
# Heuristik: typische CSRF-Token-Namen in Parametern oder Headern
TOKEN_HINT = re.compile(
    r"(csrf|xsrf|authenticity_token|_token|nonce|requestverification|"
    r"anti[-_]?forgery|__requestverificationtoken)",
    re.IGNORECASE,
)


def maybe_b64(text):
    """Burp base64-dekodieren, falls nicht schon Klartext."""
    if text is None:
        return ""
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return text


def split_http(raw):
    """Roh-HTTP in (request_line_oder_status, headers-dict, body) zerlegen."""
    head, _, body = raw.partition("\r\n\r\n")
    if not body:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    first = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return first, headers, body


def load_burp_xml(path):
    """Gibt Liste von dicts: method, url, req_headers, req_body, set_cookies."""
    items = []
    root = ET.parse(path).getroot()
    for item in root.iter("item"):
        method = (item.findtext("method") or "").upper()
        url = item.findtext("url") or ""
        req_raw = item.findtext("request") or ""
        if item.find("request") is not None and item.find("request").get("base64") == "true":
            req_raw = maybe_b64(req_raw)
        resp_raw = item.findtext("response") or ""
        if item.find("response") is not None and item.find("response").get("base64") == "true":
            resp_raw = maybe_b64(resp_raw)
        _, req_h, req_body = split_http(req_raw)
        _, resp_h, _ = split_http(resp_raw)
        items.append({
            "method": method, "url": url, "req_headers": req_h,
            "req_body": req_body,
            "set_cookies": resp_h.get("set-cookie", ""),
        })
    return items


def load_har(path):
    with open(path, encoding="utf-8") as f:
        har = json.load(f)
    items = []
    for e in har.get("log", {}).get("entries", []):
        req = e.get("request", {})
        resp = e.get("response", {})
        headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        body = req.get("postData", {}).get("text", "")
        set_cookies = "; ".join(
            f"{c['name']}={c.get('value','')}"
            + (f"; SameSite={c['sameSite']}" if c.get("sameSite") else "")
            for c in resp.get("cookies", [])
        )
        items.append({
            "method": req.get("method", "").upper(),
            "url": req.get("url", ""),
            "req_headers": headers,
            "req_body": body,
            "set_cookies": set_cookies,
        })
    return items


def samesite_of(set_cookie_header):
    """SameSite-Attribute aus Set-Cookie ziehen (grobe Heuristik, Mehrfach-Cookies)."""
    if not set_cookie_header:
        return []
    results = []
    for part in re.split(r",\s*(?=[^;,]+=)", set_cookie_header):
        cookie = SimpleCookie()
        try:
            cookie.load(part)
        except Exception:
            pass
        morsels = list(cookie.values()) or [None]
        for m in morsels:
            name = m.key if m else part.split("=", 1)[0][:30]
            ss = (m["samesite"] if m else "") or ""
            secure = bool(m["secure"]) if m else ("secure" in part.lower())
            results.append((name, ss or "(fehlt)", secure))
    return results


def analyze(item, host_filter):
    method = item["method"]
    url = item["url"]
    host = urlparse(url).netloc
    if host_filter and host_filter not in host:
        return None

    params = dict(parse_qsl(urlparse(url).query))
    params.update(dict(parse_qsl(item["req_body"])))
    header_names = set(item["req_headers"].keys())

    token_in_params = any(TOKEN_HINT.search(k) for k in params)
    token_in_headers = any(TOKEN_HINT.search(h) for h in header_names)

    ct = item["req_headers"].get("content-type", "").split(";")[0].strip().lower()
    simple = (method == "GET") or (ct in SIMPLE_CT or ct == "")

    has_origin = "origin" in header_names
    has_referer = "referer" in header_names

    cookies = samesite_of(item["set_cookies"])

    # Score: je mehr fehlt, desto heißer der Kandidat
    flags = []
    if method == "GET":
        flags.append("GET-ROUTE (Seiteneffekt manuell prüfen!)")
    if not token_in_params and not token_in_headers:
        flags.append("kein Token sichtbar")
    if simple and method != "GET":
        flags.append(f"simple request (ct={ct or 'none'})")
    if not has_origin and not has_referer:
        flags.append("kein Origin/Referer im Sample")
    for name, ss, _ in cookies:
        if ss == "(fehlt)":
            flags.append(f"Set-Cookie ohne SameSite: {name}")
        elif ss.lower() == "none":
            flags.append(f"SameSite=None: {name}")

    return {
        "method": method, "url": url, "ct": ct,
        "token": "ja(params)" if token_in_params else ("ja(header)" if token_in_headers else "nein"),
        "simple": simple, "cookies": cookies, "flags": flags,
    }


def main():
    ap = argparse.ArgumentParser(description="CSRF-Endpunkt-Inventur aus Burp-XML/HAR")
    ap.add_argument("export", help="Burp-XML oder HAR-Datei")
    ap.add_argument("--host", help="Nur Einträge dieses Hosts (Substring-Match)")
    args = ap.parse_args()

    try:
        if args.export.lower().endswith(".har") or args.export.lower().endswith(".json"):
            items = load_har(args.export)
        else:
            items = load_burp_xml(args.export)
    except Exception as e:
        sys.exit(f"Export nicht lesbar: {e}")

    seen, candidates = set(), []
    for it in items:
        key = (it["method"], it["url"].split("?")[0])
        if key in seen:
            continue
        seen.add(key)
        if it["method"] in STATE_METHODS or it["method"] == "GET":
            r = analyze(it, args.host)
            if r and (r["method"] in STATE_METHODS and (r["flags"] or r["token"] == "nein")):
                candidates.append(r)

    # Heißeste zuerst: kein Token + simple
    candidates.sort(key=lambda r: (r["token"] != "nein", not r["simple"]))

    lines = ["# CSRF-Inventur\n",
             f"Quelle: {args.export} | Kandidaten: {len(candidates)}\n",
             "| Methode | Pfad | Token | Simple? | Signale |", "|---|---|---|---|---|"]
    for c in candidates:
        path = urlparse(c["url"]).path
        lines.append(f"| {c['method']} | {path} | {c['token']} | "
                     f"{'ja' if c['simple'] else 'nein'} | {'; '.join(c['flags']) or '—'} |")

    out = "\n".join(lines)
    print(out)
    report_path = args.export + ".csrf-report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(out + "\n")
    print(f"\nReport: {report_path}")
    print("\nNächste Schritte: pro Kandidat Schutz-Diagnose (references/schutz-analyse.md),")
    print("dann Bypass-Leitern (references/bypass-leitern.md). GET-Routen manuell auf")
    print("Seiteneffekte prüfen — sie sind SameSite=Lax-taugliche Angriffsvektoren.")


if __name__ == "__main__":
    main()
