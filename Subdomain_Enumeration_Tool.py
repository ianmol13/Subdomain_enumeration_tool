# Subdomain_Enumeration_Tool.py
# Serves the custom HTML/CSS/JS frontend via Streamlit
# and handles real scan requests from the UI via st.query_params / component messaging

import streamlit as st
import streamlit.components.v1 as components
import requests
import dns.resolver
import subprocess
import pandas as pd
import json
import os
import pathlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ─────────────────────────────────────────
# PAGE CONFIG  — must be first Streamlit call
# ─────────────────────────────────────────
st.set_page_config(
    page_title="SubScan — Subdomain Enumeration",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Hide all Streamlit chrome (menu, footer, header, padding)
st.markdown("""
<style>
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stAppViewContainer"] > .main { padding: 0 !important; }
.block-container { padding: 0 !important; max-width: 100% !important; }
[data-testid="collapsedControl"] { display: none; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# BACKEND SCAN FUNCTIONS
# ─────────────────────────────────────────

def get_subdomains_crtsh(domain: str) -> list:
    """Passive recon via crt.sh SSL certificate transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return []
        results = set()
        for entry in r.json():
            for n in entry.get("name_value", "").split("\n"):
                n = n.strip().lstrip("*.")
                if n and "." in n:
                    results.add(n)
        return sorted(results)
    except Exception:
        return []


def get_subdomains_sublister(domain: str) -> list:
    """Run Sublist3r if the folder exists in the repo."""
    script_path = pathlib.Path(__file__).parent / "Sublist3r" / "sublist3r.py"
    if not script_path.exists():
        return []
    try:
        out_file = pathlib.Path(__file__).parent / "subdomains_tmp.txt"
        subprocess.run(
            ["python", str(script_path), "-d", domain, "-o", str(out_file)],
            capture_output=True, text=True, timeout=120
        )
        if out_file.exists():
            lines = [l.strip() for l in out_file.read_text().splitlines() if l.strip()]
            out_file.unlink(missing_ok=True)
            return lines
    except Exception:
        pass
    return []


def brute_force_subdomains(domain: str) -> list:
    """DNS brute-force using common_subdomains.txt wordlist."""
    wordlist_path = pathlib.Path(__file__).parent / "common_subdomains.txt"
    if not wordlist_path.exists():
        return []
    found = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    try:
        for line in wordlist_path.read_text().splitlines():
            word = line.strip()
            if not word:
                continue
            fqdn = f"{word}.{domain}"
            try:
                resolver.resolve(fqdn, "A")
                found.append(fqdn)
            except Exception:
                pass
    except Exception:
        pass
    return found


def run_scan(domain: str, methods: list, workers: int = 3) -> dict:
    """
    Run requested scan methods in parallel.
    Returns dict with results list and log list.
    """
    results = []
    logs = []
    seen = set()
    t0 = datetime.utcnow()

    logs.append(f"[{t0.strftime('%H:%M:%S')}] Scan started — target: {domain}")

    tasks = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        if "crtsh" in methods:
            tasks.append(("crtsh", executor.submit(get_subdomains_crtsh, domain)))
        if "sublister" in methods:
            tasks.append(("sublister", executor.submit(get_subdomains_sublister, domain)))
        if "brute" in methods:
            tasks.append(("brute", executor.submit(brute_force_subdomains, domain)))

        for method, fut in tasks:
            try:
                found = fut.result()
            except Exception as e:
                logs.append(f"[ERROR] {method}: {e}")
                found = []

            new_count = 0
            for sub in found:
                if sub not in seen:
                    seen.add(sub)
                    results.append({"subdomain": sub, "source": method, "domain": domain})
                    new_count += 1

            ts = datetime.utcnow().strftime("%H:%M:%S")
            logs.append(f"[{ts}] [{method}] {domain} → {new_count} new subdomains")

    elapsed = (datetime.utcnow() - t0).total_seconds()
    logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Scan complete — {len(results)} total in {elapsed:.1f}s")

    return {"results": results, "logs": logs, "elapsed": round(elapsed, 1)}


# ─────────────────────────────────────────
# HANDLE SCAN REQUEST FROM FRONTEND
# Streamlit receives scan params via query string:
#   ?scan=1&domain=example.com&methods=crtsh,brute&workers=3
# ─────────────────────────────────────────

params = st.query_params

if params.get("scan") == "1":
    domain = params.get("domain", "").strip().lower()
    methods_raw = params.get("methods", "crtsh")
    methods = [m.strip() for m in methods_raw.split(",") if m.strip()]
    workers = int(params.get("workers", 3))

    if domain and methods:
        scan_data = run_scan(domain, methods, workers)
        # Return JSON to the page
        st.markdown(f"""
<script>
window.parent.postMessage({{
  type: 'SUBSCAN_RESULT',
  data: {json.dumps(scan_data)}
}}, '*');
</script>
""", unsafe_allow_html=True)
    st.stop()


# ─────────────────────────────────────────
# SERVE THE HTML FRONTEND
# ─────────────────────────────────────────

html_path = pathlib.Path(__file__).parent / "subscan.html"

if html_path.exists():
    html_content = html_path.read_text(encoding="utf-8")
    components.html(html_content, height=1000, scrolling=True)
else:
    st.error("subscan.html not found. Make sure it is in the same folder as this file.")
    st.code("Expected location: " + str(html_path))
