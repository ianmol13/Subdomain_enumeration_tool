import streamlit as st
import streamlit.components.v1 as components
import requests
import dns.resolver
import subprocess
import json
import re
import pathlib
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="SubScan", page_icon="◈", layout="wide", initial_sidebar_state="collapsed")

# hide streamlit's default UI chrome
st.markdown("""
<style>
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stAppViewContainer"] > .main { padding: 0 !important; }
.block-container { padding: 0 !important; max-width: 100% !important; }
[data-testid="collapsedControl"] { display: none; }
</style>
""", unsafe_allow_html=True)

BASE = pathlib.Path(__file__).parent
WORDLIST = BASE / "common_subdomains.txt"
DNS_TO = 4      # dns timeout
HTTP_TO = 6     # http timeout
MAX_W = 30      # max thread workers

# fallback wordlist if user hasn't added common_subdomains.txt yet
_DEFAULT_WORDS = [
    "www", "mail", "smtp", "pop", "imap", "webmail", "mx",
    "ns1", "ns2", "api", "api-v1", "rest", "graphql", "gateway",
    "cdn", "static", "assets", "media", "img",
    "dev", "staging", "stage", "uat", "qa", "test", "sandbox",
    "demo", "preview", "alpha", "beta", "prod", "production",
    "admin", "dashboard", "panel", "console", "portal",
    "app", "mobile", "m", "auth", "login", "sso", "oauth",
    "shop", "store", "pay", "billing",
    "blog", "news", "help", "support", "docs", "wiki",
    "git", "gitlab", "jenkins", "ci", "grafana", "kibana",
    "vpn", "remote", "bastion",
    "db", "mysql", "postgres", "redis", "mongo", "backup",
    "intranet", "internal", "corp", "status", "health", "monitor",
    "autodiscover", "exchange", "ftp", "sftp",
]


def _ts():
    return datetime.utcnow().strftime("%H:%M:%S")


def _clean(raw, root):
    s = raw.strip().lstrip("*.").lower()
    if not s or "." not in s:
        return None
    if s == root or s.endswith("." + root):
        return s
    return None


def _valid_domain(d):
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", d))


# --- wildcard check ---
# resolves a random subdomain to see if everything resolves (wildcard)
def check_wildcard(domain):
    probe = f"_subscan_nowildcard_{int(time.time())}.{domain}"
    try:
        ans = dns.resolver.resolve(probe, "A", lifetime=DNS_TO)
        ips = [r.address for r in ans]
        return True, ips[0] if ips else None
    except Exception:
        return False, None


# --- enumeration sources ---

def from_crtsh(domain):
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200:
            return []
        found = set()
        for e in r.json():
            for n in e.get("name_value", "").split("\n"):
                s = _clean(n, domain)
                if s:
                    found.add(s)
        return sorted(found)
    except Exception:
        return []


def from_hackertarget(domain):
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200 or "error" in r.text[:50].lower():
            return []
        found = set()
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                s = _clean(parts[0], domain)
                if s:
                    found.add(s)
        return sorted(found)
    except Exception:
        return []


def from_alienvault(domain):
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200:
            return []
        found = set()
        for rec in r.json().get("passive_dns", []):
            s = _clean(rec.get("hostname", ""), domain)
            if s:
                found.add(s)
        return sorted(found)
    except Exception:
        return []


def from_rapiddns(domain):
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=15, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200:
            return []
        found = set()
        pattern = r'<td>([a-zA-Z0-9.\-]+\.' + re.escape(domain) + r')</td>'
        for m in re.findall(pattern, r.text):
            s = _clean(m, domain)
            if s:
                found.add(s)
        return sorted(found)
    except Exception:
        return []


def from_bufferover(domain):
    try:
        r = requests.get(
            f"https://dns.bufferover.run/dns?q=.{domain}",
            timeout=12, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code != 200:
            return []
        data = r.json()
        found = set()
        for rec in data.get("FDNS_A", []) + data.get("RDNS", []):
            for part in rec.split(","):
                s = _clean(part, domain)
                if s:
                    found.add(s)
        return sorted(found)
    except Exception:
        return []


def from_virustotal(domain):
    # no api key needed for this endpoint, limited results but still useful
    try:
        r = requests.get(
            f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        if r.status_code != 200:
            return []
        found = set()
        for item in r.json().get("data", []):
            s = _clean(item.get("id", ""), domain)
            if s:
                found.add(s)
        return sorted(found)
    except Exception:
        return []


def from_sublister(domain):
    script = BASE / "Sublist3r" / "sublist3r.py"
    if not script.exists():
        return []
    outfile = BASE / f"_tmp_{domain}.txt"
    try:
        subprocess.run(
            ["python", str(script), "-d", domain, "-o", str(outfile), "-t", "10"],
            capture_output=True, text=True, timeout=120
        )
        if outfile.exists():
            lines = outfile.read_text().splitlines()
            outfile.unlink(missing_ok=True)
            return [s for s in (_clean(l.strip(), domain) for l in lines if l.strip()) if s]
    except Exception:
        pass
    finally:
        if outfile.exists():
            outfile.unlink(missing_ok=True)
    return []


def _try_resolve(fqdn, resolver):
    try:
        resolver.resolve(fqdn, "A", lifetime=DNS_TO)
        return fqdn
    except Exception:
        return None


def from_bruteforce(domain, wildcard_ip=None):
    words = (
        [l.strip() for l in WORDLIST.read_text().splitlines() if l.strip()]
        if WORDLIST.exists() else _DEFAULT_WORDS
    )
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TO
    found = []

    with ThreadPoolExecutor(max_workers=MAX_W) as ex:
        futs = {ex.submit(_try_resolve, f"{w}.{domain}", resolver): w for w in words}
        for fut in as_completed(futs):
            res = fut.result()
            if not res:
                continue
            # skip wildcard hits
            if wildcard_ip:
                try:
                    ans = resolver.resolve(res, "A", lifetime=DNS_TO)
                    if any(r.address == wildcard_ip for r in ans):
                        continue
                except Exception:
                    pass
            found.append(res)

    return sorted(found)


# maps frontend pill keys to functions
SOURCES = {
    "crtsh": from_crtsh,
    "hackertarget": from_hackertarget,
    "alienvault": from_alienvault,
    "rapiddns": from_rapiddns,
    "bufferover": from_bufferover,
    "virustotal": from_virustotal,
    "sublister": from_sublister,
    "brute": from_bruteforce,
}

SOURCE_SCORE = {
    "crtsh": 20, "hackertarget": 15, "alienvault": 15,
    "rapiddns": 10, "bufferover": 10, "virustotal": 15,
    "sublister": 10, "brute": 10,
}


# --- dns enrichment ---

def get_dns_records(subdomain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TO
    info = {"A": [], "AAAA": [], "CNAME": None, "MX": [], "NS": [], "TXT": []}

    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        try:
            ans = resolver.resolve(subdomain, rtype, lifetime=DNS_TO)
            if rtype == "A":
                info["A"] = [r.address for r in ans]
            elif rtype == "AAAA":
                info["AAAA"] = [r.address for r in ans]
            elif rtype == "CNAME":
                info["CNAME"] = str(ans[0].target).rstrip(".")
            elif rtype == "MX":
                info["MX"] = [str(r.exchange).rstrip(".") for r in ans]
            elif rtype == "NS":
                info["NS"] = [str(r.target).rstrip(".") for r in ans]
            elif rtype == "TXT":
                info["TXT"] = [b"".join(r.strings).decode(errors="ignore") for r in ans]
        except Exception:
            pass

    return info


# --- http probing ---

_TECH = {
    "nginx": r"nginx",
    "apache": r"Apache",
    "cloudflare": r"cloudflare",
    "aws": r"amazonaws|CloudFront",
    "vercel": r"vercel",
    "wordpress": r"wp-content|wordpress",
    "django": r"csrftoken",
    "laravel": r"laravel_session",
    "rails": r"_rails_session",
    "react": r"__next|_next/static",
    "iis": r"Microsoft-IIS",
    "tomcat": r"Apache-Coyote",
    "fastly": r"Fastly",
}


def get_page_title(html):
    m = re.search(r"<title[^>]*>([^<]{1,180})</title>", html, re.I)
    return m.group(1).strip() if m else None


def detect_tech(headers, body):
    blob = " ".join(f"{k}: {v}" for k, v in headers.items()) + " " + body[:3000]
    return [t for t, pat in _TECH.items() if re.search(pat, blob, re.I)]


def http_probe(subdomain):
    result = {"alive": False, "status": None, "url": None,
              "redirect": None, "title": None, "tech": [], "response_ms": None}

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            t0 = time.monotonic()
            r = requests.get(
                url, timeout=HTTP_TO, allow_redirects=True, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SubScan)"}
            )
            ms = round((time.monotonic() - t0) * 1000)
            result.update({
                "alive": True,
                "status": r.status_code,
                "url": r.url,
                "response_ms": ms,
                "title": get_page_title(r.text),
                "tech": detect_tech(dict(r.headers), r.text),
                "redirect": r.url if r.url != url else None,
            })
            break
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue

    return result


def confidence(sources, dns_info, http_info):
    score = sum(SOURCE_SCORE.get(s, 5) for s in sources)
    if dns_info.get("A"):
        score += 20
    if http_info.get("alive"):
        score += 20
    return min(score, 100)


# --- main scan ---

def run_scan(domain, methods, workers=10, enrich=True, probe=True):
    logs = []
    t0 = datetime.utcnow()

    if not _valid_domain(domain):
        return {"error": f"invalid domain: {domain}", "results": [], "logs": []}

    logs.append(f"[{_ts()}] starting scan on {domain}")
    logs.append(f"[{_ts()}] sources: {', '.join(methods)}")

    wc, wc_ip = check_wildcard(domain)
    if wc:
        logs.append(f"[{_ts()}] wildcard detected ({wc_ip}) — brute results will be filtered")
    else:
        logs.append(f"[{_ts()}] no wildcard — good")

    # run all sources in parallel
    seen = {}  # subdomain -> set of sources

    def _run(method):
        fn = SOURCES.get(method)
        if not fn:
            return method, []
        result = fn(domain, wc_ip) if method == "brute" else fn(domain)
        return method, result

    active = [m for m in methods if m in SOURCES]
    with ThreadPoolExecutor(max_workers=min(len(active) or 1, 8)) as ex:
        futs = {ex.submit(_run, m): m for m in active}
        for fut in as_completed(futs):
            method, found = fut.result()
            logs.append(f"[{_ts()}] {method} -> {len(found)} results")
            for sub in found:
                seen.setdefault(sub, set()).add(method)

    logs.append(f"[{_ts()}] {len(seen)} unique subdomains after dedup")

    if not seen:
        elapsed = round((datetime.utcnow() - t0).total_seconds(), 1)
        logs.append(f"[{_ts()}] done, nothing found ({elapsed}s)")
        return {"results": [], "logs": logs, "stats": {}, "elapsed": elapsed}

    # dns enrichment
    dns_cache = {}
    if enrich:
        logs.append(f"[{_ts()}] enriching dns for {len(seen)} hosts...")
        with ThreadPoolExecutor(max_workers=MAX_W) as ex:
            futs = {ex.submit(get_dns_records, sub): sub for sub in seen}
            for fut in as_completed(futs):
                dns_cache[futs[fut]] = fut.result()
        logs.append(f"[{_ts()}] dns enrichment done")
    else:
        dns_cache = {sub: {} for sub in seen}

    # http probe — only bother with hosts that have an A record
    http_cache = {}
    if probe:
        targets = [s for s in seen if dns_cache.get(s, {}).get("A")]
        logs.append(f"[{_ts()}] probing {len(targets)} live hosts over http...")
        with ThreadPoolExecutor(max_workers=MAX_W) as ex:
            futs = {ex.submit(http_probe, sub): sub for sub in targets}
            for fut in as_completed(futs):
                http_cache[futs[fut]] = fut.result()
        alive = sum(1 for h in http_cache.values() if h.get("alive"))
        logs.append(f"[{_ts()}] {alive}/{len(targets)} hosts responded")
    else:
        http_cache = {sub: {} for sub in seen}

    results = []
    for sub, srcs in seen.items():
        d = dns_cache.get(sub, {})
        h = http_cache.get(sub, {})
        results.append({
            "subdomain": sub,
            "domain": domain,
            "sources": sorted(srcs),
            "source": sorted(srcs)[0],
            "confidence": confidence(list(srcs), d, h),
            "ip": d.get("A", []),
            "ipv6": d.get("AAAA", []),
            "cname": d.get("CNAME"),
            "mx": d.get("MX", []),
            "ns": d.get("NS", []),
            "txt": d.get("TXT", []),
            "alive": h.get("alive", False),
            "status": h.get("status"),
            "url": h.get("url"),
            "redirect": h.get("redirect"),
            "title": h.get("title"),
            "tech": h.get("tech", []),
            "response_ms": h.get("response_ms"),
        })

    results.sort(key=lambda x: (-x["confidence"], x["subdomain"]))

    alive_results = [r for r in results if r["alive"]]
    elapsed = round((datetime.utcnow() - t0).total_seconds(), 1)

    stats = {
        "total": len(results),
        "alive": len(alive_results),
        "sources_used": len(active),
        "wildcard": wc,
        "wildcard_ip": wc_ip,
        "elapsed": elapsed,
        "scanned_at": t0.isoformat() + "Z",
    }

    logs.append(f"[{_ts()}] scan complete — {len(results)} found, {len(alive_results)} alive, took {elapsed}s")
    return {"results": results, "logs": logs, "stats": stats, "elapsed": elapsed}


# --- session history ---

def push_history(domain, stats):
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    st.session_state.scan_history.insert(0, {
        "domain": domain,
        "total": stats.get("total", 0),
        "alive": stats.get("alive", 0),
        "elapsed": stats.get("elapsed", 0),
        "scanned_at": stats.get("scanned_at", _ts()),
    })
    st.session_state.scan_history = st.session_state.scan_history[:20]


def get_history():
    return st.session_state.get("scan_history", [])


# --- request handling ---
# frontend talks to us via query params, we respond via postMessage

params = st.query_params

if params.get("scan") == "1":
    domain = params.get("domain", "").strip().lower()
    raw_methods = params.get("methods", "crtsh,hackertarget,alienvault")
    methods = [m.strip() for m in raw_methods.split(",") if m.strip()]
    workers = min(int(params.get("workers", 10)), MAX_W)
    do_enrich = params.get("enrich", "1") == "1"
    do_probe = params.get("probe", "1") == "1"

    if domain:
        data = run_scan(domain, methods, workers, do_enrich, do_probe)
        push_history(domain, data.get("stats", {}))
        st.markdown(f"""
<script>
window.parent.postMessage({{ type: 'SUBSCAN_RESULT', data: {json.dumps(data)} }}, '*');
</script>
""", unsafe_allow_html=True)
    st.stop()

if params.get("action") == "history":
    st.markdown(f"""
<script>
window.parent.postMessage({{ type: 'SUBSCAN_HISTORY', data: {json.dumps(get_history())} }}, '*');
</script>
""", unsafe_allow_html=True)
    st.stop()

# serve frontend
html = BASE / "subscan.html"
if html.exists():
    components.html(html.read_text(encoding="utf-8"), height=1080, scrolling=True)
else:
    st.error("can't find subscan.html — make sure it's in the same folder as this file")
