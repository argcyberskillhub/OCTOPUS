"""Web info / security module. Passive (HTTP/HTTPS/TLS) & public DNS lookups.
Target URL supplied should route to assets you administrate or are authorized
to inspect."""

from __future__ import annotations
from ..core.colors import module_banner
WEB_BANNER = r"""
 __        __     _            ___        __
 \ \      / /__  | |__        |_ _|_ __  / _| ___
  \ \ /\ / / _ \ | '_ \   ___  | || '_ \| |_ / _ \
   \ V  V /  __/ | |_) | |___| | || | | |  _| |_| |
    \_/\_/ \___| |_.__/       |___|_| |_|_|  \___/

                  web-info
            Coded by : argcyberskillhub

"""



def show_banner():
    print(module_banner(WEB_BANNER, "web-info"))

import ssl
import socket
import json
import re
import urllib.request
import urllib.parse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.ui import (
    section, ok, info, warn, err, get_str, yes_no,
    spinner, wait_or_exit, print_two_col
)
from ..core.export import prompt_export


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")

TLS_FINGERPRINT = {}   # placeholder for future HSTS/NPN

def _norm(u):
    return u if u.startswith("http") else "https://" + u


def _host_of(u):
    return urllib.parse.urlparse(_norm(u)).netloc


def fetch(u, timeout=12, method="GET"):
    req = urllib.request.Request(_norm(u), headers={"User-Agent": UA},
                                 method=method)
    return urllib.request.urlopen(req, timeout=timeout)


# ---- 1 HTTP headers -----------------------------------------------
def http_headers():
    section("HTTP response headers")
    u = get_str("URL") or ""
    if not u:
        return
    try:
        with fetch(u) as r:
            ok(f"{r.status} {r.reason}  final={r.geturl()}")
            rows = [(k, v) for k, v in r.headers.items()]
            print_two_col(["Header", "Value"], rows)
    except Exception as e:
        err(f"Request failed: {e}")
    wait_or_exit()


# ---- 2 TLS cert ----------------------------------------------------
def tls_cert():
    section("TLS/SSL certificate information")
    host = get_str("Hostname") or ""
    if not host:
        return
    port = get_int("Port", 443)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        info(f"Subject : {dict(x[0] for x in cert['subject'])}")
        info(f"Issuer  : {dict(x[0] for x in cert['issuer'])}")
        info(f"Version : {cert.get('version')}")
        info(f"Serial  : {cert.get('serialNumber')}")
        a = cert["notAfter"]; b = cert["notBefore"]
        info(f"Valid   : {b} -> {a}")
        try:
            na = datetime.strptime(a, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            na = None
        if na:
            days = (na - datetime.now()).days
            if days < 30:
                warn(f"Certificate expires soon ({days} days).")
            else:
                ok(f"{days} days until expiry.")
        print_two_col(["SANs"], [[s] for s in cert.get("subjectAltName", [])])
    except Exception as e:
        err(f"TLS handshake failed: {e}")
    wait_or_exit()


# ---- 3 DNS records (reuse network.dns_lookup style) ----------------
def dns_records():
    section("DNS records")
    import network as _  # reuse network module
    host = get_str("Hostname") or ""
    if not host:
        return
    network.dns_lookup.__globals__["section"]  # not used
    from . import network
    # drift small helper instead of importing
    try:
        import dns.resolver
    except Exception:
        err("Requires dnspython"); return
    result = {"host": host}
    for t in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            ans = dns.resolver.resolve(host, t)
            result[t] = [str(x) for x in ans]
            ok(f"{t:>5}: " + ", ".join(str(x) for x in ans))
        except Exception as e:
            result[t] = f"none ({type(e).__name__})"
            info(f"{t:>5}: none")
    prompt_export(result, f"webdns_{host}")
    wait_or_exit()


def whoisq():
    from .network import whois_lookup
    whois_lookup()


# ---- 4 robots.txt & sitemap ----------------------------------------
def robots_check():
    section("robots.txt checker")
    u = get_str("URL (domain)") or ""
    if not u:
        return
    u = _norm(u).rstrip("/") + "/robots.txt"
    try:
        with fetch(u) as r:
            ok(f"robots.txt found (HTTP {r.status}). Policies:")
            print(r.read(4000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            ok("No robots.txt (HTTP 404) - search engines may crawl everything.")
        elif e.code in (401, 403):
            warn(f"robots.txt blocked (HTTP {e.code}).")
        else:
            err(f"HTTP {e.code}")
    except Exception as e:
        err(f"Unreachable: {e}")
    wait_or_exit()


def sitemap_check():
    section("sitemap.xml checker")
    u = get_str("URL") or ""
    if not u:
        return
    u = _norm(u).rstrip("/") + "/sitemap.xml"
    try:
        with fetch(u) as r:
            body = r.read(6000).decode("utf-8", "replace")
            ok(f"sitemap.xml delivered (HTTP {r.status}, "
               f"{len(body)} bytes read).")
            print(body[:2000])
    except Exception:
        warn("No sitemap.xml at root (may exist elsewhere or not at all).")
    wait_or_exit()


# ---- 6 security headers -----------------------------------------
SEC_MISS_HEADERS = {
    "Strict-Transport-Security": "HSTS missing - protects against SSL-stripping",
    "X-Frame-Options": "Clickjacking protection missing",
    "Content-Security-Policy": "CSP missing - XSS impact mitigation absent",
    "X-Content-Type-Options": "MIME sniffing prevention missing",
    "Referrer-Policy": "Referrer policy not set",
    "Permissions-Policy": "Permissions policy not set",
}


def security_headers():
    section("Security-header checker")
    u = get_str("URL") or ""
    if not u:
        return
    try:
        with fetch(u) as r:
            hd = {k.lower(): v for k, v in r.headers.items()}
            ok(f"Present and security-relevant headers on {r.geturl()}:")
            shown = False
            for need, desc in SEC_MISS_HEADERS.items():
                if need.lower() in hd:
                    shown = True
                    ok(f"  {need:<42} present")
                else:
                    warn(f"  {need:<42} missing -> {desc}")
            if not shown:
                info("No security headers observed.")
    except Exception as e:
        err(str(e))
    wait_or_exit()


# ---- tech detection ------------------------------------------------
def tech_detect():
    section("Technology / framework detection")
    u = get_str("URL") or ""
    if not u:
        return
    sig = {"server": None, "headers": {}, "title": None,
           "generator": None, "frameworks": []}
    try:
        with fetch(u) as r:
            sig["server"] = r.headers.get("Server")
            sig["headers"] = {k: v for k, v in r.headers.items()
                              if k.lower() in ("x-powered-by", "x-aspnet-version",
                                               "via", "x-nginx-version")}
            html = r.read(200_000).decode("utf-8", "replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            sig["title"] = m.group(1).strip()[:120] if m else None
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                            html, re.I)
            sig["generator"] = gen.group(1) if gen else None

        # signature bucket
        h = {k.lower(): (" " + v + " ").lower() for k, v in
             (sig["headers"] or {}).items()}
        alls = str(h) + (sig["generator"] or "").lower()
        if "wordpress" in alls: sig["frameworks"].append("WordPress")
        if "drupal" in alls: sig["frameworks"].append("Drupal")
        if "rails" in alls or "phusion" in alls: sig["frameworks"].append("Ruby/Rails")
        if "asp.net" in alls or "asp" in alls: sig["frameworks"].append("ASP.NET")
        if "express" in alls or "node" in alls: sig["frameworks"].append("Node")
        if "nginx" in (sig["server"] or "").lower(): sig["frameworks"].append("nginx")
        if "apache" in (sig["server"] or "").lower(): sig["frameworks"].append("Apache")
        if "cloudflare" in alls: sig["frameworks"].append("Cloudflare (proxy)")

        for k_, v_ in sig.items():
            if v_:
                print(f"  {k_:<14}: {v_}")
        if not sig["frameworks"]:
            info("No obvious framework fingerprint (public response only).")
        prompt_export(sig, f"tech_{_host_of(u)}")
    except Exception as e:
        err(f"Request error: {e}")
    wait_or_exit()


# ---- http status ---------------------------------------------------
def http_status():
    section("HTTP status checker")
    u = get_str("URL") or ""
    if not u:
        return
    try:
        with fetch(u) as r:
            ok(f"{r.status} {r.reason}  final URL: {r.geturl()}")
    except urllib.error.HTTPError as e:
        warn(f"HTTP {e.code} {e.reason}  (server responded; page errored)")
    except Exception as e:
        err(f"No response: {e}")
    wait_or_exit()


# ---- redirect analysis -------------------------------------------
def redirect_analysis():
    section("Redirect analysis")
    u = get_str("URL") or ""
    if not u:
        return
    chain, cur = [], u
    seen = set()
    hops = 0
    while hops < 10:
        try:
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
            o = urllib.request.build_opener(NoRedir)
            req = urllib.request.Request(cur, headers={"User-Agent": UA},
                                         method="GET")
            with o.open(req, timeout=12) as r:
                chain.append((cur, r.status))
                break
        except urllib.error.HTTPError as e:
            chain.append((cur, e.code))
            red = e.headers.get("Location")
            if not red:
                break
            cur = urllib.parse.urljoin(cur, red)
            if cur in seen:
                break
            seen.add(cur)
            hops += 1
        except urllib.error.URLError as e:
            chain.append((cur, "connection error"))
            break
    for i, (u_, code_) in enumerate(chain):
        arrow = "  ->  " if i else " start "
        info(f"{arrow}{u_}  [HTTP {code_}]")
    prompt_export({"chain": chain, "hops": len(chain)}, "redirects")
    wait_or_exit()


# ---- cookies -----------------------------------------------------
def cookie_inspect():
    section("Cookie / security-flag inspection")
    u = get_str("URL") or ""
    if not u:
        return
    cookies = {}
    try:
        import http.cookiejar
        cj = http.cookiejar.CookieJar()
        o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        with o.open(_norm(u), timeout=12) as r:
            r.read(1000)
        for c in cj:
            flags = []
            if c.secure: flags.append("Secure")
            if c.has_nonstandard_attr and c.has_nonstandard_attr("HttpOnly"):
                flags.append("HttpOnly")
            # fine-grained:
            if c.has_nonstandard_attr("HttpOnly"):
                flags.append("HttpOnly")
            if c.has_nonstandard_attr("SameSite"):
                flags.append("SameSite=" + c.has_nonstandard_attr("SameSite"))
            cookies[c.name] = {"value_len": len(c.value or ""),
                               "flags": flags, "domain": c.domain,
                               "path": c.path}
            ok(f"{c.name}: flags={flags or ['none (in JavaScript scope!)']}")
            if not flags:
                warn(f"  => cookie '{c.name}' lacks Secure/HttpOnly; risky for "
                     "session tokens.")
        prompt_export(cookies, f"cookies_{_host_of(u)}")
    except Exception as e:
        err(str(e))
    wait_or_exit()


# ---- subdomain discovery (passive) -------------------------------
def subdomain_discover():
    section("Subdomain discovery (passive / public sources)")
    dm = get_str("Domain") or ""
    if not dm:
        return
    subs = set()
    info("Probing public, unauthenticated sources (crt.sh certificate logs)...")
    import urllib.request
    try:
        import json
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dm)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode())
        for row in data:
            name = row.get("name_value", "")
            for one in name.split("\n"):
                one = one.strip().lower()
                if one.endswith("." + dm) or one == dm:
                    subs.add(one)
                # also match wildcard pattern
                if " *." in one or one.startswith("*."):
                    subs.add(one.replace("*.", ""))
    except Exception as e:
        warn(f"crt.sh query failed: {e}")
    subs = {s for s in subs if s.endswith("." + dm) or s == dm}
    subs = sorted(subs)
    ok(f"Found {len(subs)} public subdomain names (certificate transparency):")
    for s in subs:
        print("   . " + s)
    if not subs:
        info("None listed via this public source.")
    prompt_export({"domain": dm, "passive_subdomains": subs},
                  f"subs_{dm}")
    wait_or_exit()


# ---- url/domain info ----------------------------------------------
def url_info():
    section("URL / domain information")
    u = get_str("URL") or ""
    if not u:
        return
    u = _norm(u)
    pu = urllib.parse.urlparse(u)
    host = pu.netloc
    info(f"Scheme      : {pu.scheme}")
    info(f"Host        : {host}")
    try:
        info(f"IP address  : {socket.gethostbyname(pu.hostname)}")
        # reverse ptr
        try:
            ptr = socket.gethostbyaddr(pu.hostname)
            info("PTR (rev)   : " + ptr[0])
        except Exception:
            info("PTR (rev)   : n/a")
    except Exception as e:
        err(f"Resolution failed: {e}")
    portinfo = {"default_for_web": pu.port or (443 if pu.scheme == "https" else 80)}
    info(f"Port        : {portinfo['default_for_web']}")
    info(f"Path        : {pu.path or '/'}")
    # quick whoami (public geo is skipped - not needed)
    info("Resource is a " + ("HTTPS-encrypted web endpoint." if pu.scheme=="https"
                             else "plain-HTTP endpoint."))
    if pu.scheme != "https":
        warn("Plain HTTP - credentials/tokens traverse the network unencrypted.")
    prompt_export({"url": u, "parsed": {k: v for k, v in pu._asdict().items()}},
                  f"urlinfo_{host}")
    wait_or_exit()


# ---- misconfig checks ---------------------------------------------
def miscon_check():
    section("Basic web misconfiguration checks")
    u = get_str("URL") or ""
    if not u:
        return
    u = _norm(u).rstrip("/")
    findings = []
    probes = ["/.git/HEAD", "/.env", "/server-status", "/.DS_Store",
              "/wp-config.php", "/phpinfo.php", "/backup.zip", "/robots.txt"]
    info(f"Probing a small, fixed list of common misconfig paths on {u} (GET, "
         "single request each, plaintext-only). Full traversal/brute is out of "
         "scope here.")
    with spinner():
        for path in probes:
            full = u + path
            code, reveals = _probe_mis(full, path)
            if code and code < 400:
                if reveals:
                    warn(f"  EXPOSED  HTTP {code}  {path}  => sensitive data")
                    findings.append({"path": path, "status": code,
                                     "exposed": True})
                else:
                    info(f"  present HTTP {code}  {path}  (may be benign)")
                    findings.append({"path": path, "status": code,
                                     "exposed": False})
            else:
                pass
    if not findings:
        ok("No obvious public misconfigurations found on the probed paths.")
    prompt_export(findings, f"misconfig_{_host_of(u)}")
    wait_or_exit()


def _probe_mis(url, path):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read(64).decode("utf-8", "replace")
            # simple reveal heuristic
            sens = [".git", "password", "root:", "APP_KEY", "DB_PASSWORD"]
            reveal = any(s in body for s in sens)
            return r.status, reveal
    except urllib.error.HTTPError as e:
        return None, False
    except Exception:
        return None, False
