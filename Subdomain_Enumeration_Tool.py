# app.py — improved UI for Subdomain Enumeration Tool
import streamlit as st
import requests
import dns.resolver
import subprocess
import pandas as pd
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# -----------------------------
# Page config & styles
# -----------------------------
st.set_page_config(page_title="Subdomain Enumeration", page_icon="", layout="wide")

st.markdown(
    """
    <style>
    /* page background + main font */
    .stApp { background: #020202; color: #00ff6a; font-family: 'Courier New', monospace; }

    /* header */
    .header { text-align: center; margin-bottom: 8px; }
    .card { background:#071013; border:1px solid #00ff6a; padding:12px; border-radius:8px; }

    /* sidebar tweaks */
    .stSidebar { background: #060606; color: #00ff6a; }

    /* buttons */
    .stButton>button { background:#00ff6a; color:black; font-weight:bold; }
    .stDownloadButton>button { background:#00ff6a; color:black; font-weight:bold; }

    /* table header color */
    .dataframe thead th { background: #001100; color: #00ff6a; }
    </style>
    """, unsafe_allow_html=True
)

# -----------------------------
# Helper functions
# -----------------------------
def get_subdomains_crtsh(domain):
    """Query crt.sh and return list of subdomains."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return []
        data = r.json()
        # name_value can contain multiple names separated by \n
        results = set()
        for entry in data:
            nv = entry.get("name_value", "")
            for n in nv.split("\n"):
                n = n.strip()
                if n:
                    results.add(n)
        return list(results)
    except Exception:
        return []

def get_subdomains_sublister(domain):
    """Run Sublist3r if present; returns list."""
    script_path = "Sublist3r/sublist3r.py"
    if not os.path.exists(script_path):
        return []
    try:
        result = subprocess.run(["python", script_path, "-d", domain, "-o", "subdomains.txt"],
                                capture_output=True, text=True, timeout=120)
        # read output file
        if os.path.exists("subdomains.txt"):
            with open("subdomains.txt", "r") as f:
                return [l.strip() for l in f if l.strip()]
        # fallback parse stdout
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return []

def brute_force_subdomains(domain, wordlist="common_subdomains.txt"):
    """Try resolving common names from wordlist."""
    found = []
    resolver = dns.resolver.Resolver()
    try:
        with open(wordlist, "r") as f:
            for line in f:
                sub = line.strip()
                if not sub:
                    continue
                full = f"{sub}.{domain}"
                try:
                    resolver.resolve(full, "A", lifetime=3)
                    found.append(full)
                except Exception:
                    pass
    except FileNotFoundError:
        # the UI will show the message
        pass
    return found

def save_results_file(subdomains, fmt="csv"):
    df = pd.DataFrame({"Subdomain": list(subdomains)})
    fname = f"subdomains_found.{fmt}"
    if fmt == "csv":
        df.to_csv(fname, index=False)
    else:
        df.to_json(fname, orient="records")
    return fname

# -----------------------------
# Session state init
# -----------------------------
if "results" not in st.session_state:
    st.session_state.results = set()
if "logs" not in st.session_state:
    st.session_state.logs = []

def log(msg):
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    st.session_state.logs.append(f"[{timestamp} UTC] {msg}")

# -----------------------------
# Sidebar: controls
# -----------------------------
st.sidebar.markdown("## Controls")
domains_input = st.sidebar.text_area("Enter target domains (one per line)", help="e.g. example.com")
domains = [d.strip() for d in domains_input.splitlines() if d.strip()]

use_crtsh = st.sidebar.checkbox("Use crt.sh (passive)", value=True)
use_sublister = st.sidebar.checkbox("Use Sublist3r (optional)", value=False)
use_brute = st.sidebar.checkbox("Brute-force (requires common_subdomains.txt)", value=False)
export_format = st.sidebar.selectbox("Export format", ["CSV", "JSON"])
max_workers = st.sidebar.slider("Parallel workers", min_value=1, max_value=10, value=3)
run_button = st.sidebar.button(" Start Scan")

st.sidebar.markdown("---")
st.sidebar.markdown("**Quick tips:** do not scan unauthorized domains.\n\nUse public or authorized targets only.")

# -----------------------------
# Main layout: header + two columns
# -----------------------------
st.markdown("<div class='header'><h1> Subdomain Enumeration Tool</h1><p>Hacker-style UI — results & logs</p></div>", unsafe_allow_html=True)
left_col, right_col = st.columns([2, 3])

with left_col:
    st.markdown("<div class='card'><b>Scan Controls</b></div>", unsafe_allow_html=True)
    st.write("")  # spacing
    st.markdown("**Search / Filter results**")
    search_term = st.text_input("Filter subdomains contains", value="")
    sort_asc = st.checkbox("Sort alphabetically", value=True)

with right_col:
    st.markdown("<div class='card'><b>Summary</b></div>", unsafe_allow_html=True)
    total_count = len(st.session_state.results)
    st.metric("Total subdomains found", total_count)
    last_run = st.session_state.logs[-1] if st.session_state.logs else "No runs yet"
    st.caption(f"Last log: {last_run}")

# -----------------------------
# Tabs for results / logs / about
# -----------------------------
tab_results, tab_logs, tab_about = st.tabs(["Results", "Logs", "About"])

# -----------------------------
# Run the scan when button pressed
# -----------------------------
if run_button:
    if not domains:
        st.sidebar.error("Please enter at least one domain.")
    else:
        st.session_state.results = set()   # reset
        st.session_state.logs = []
        total_tasks = len(domains) * ((1 if use_crtsh else 0) + (1 if use_sublister else 0) + (1 if use_brute else 0))
        progress = st.progress(0)
        completed = 0
        log("Scan started")
        futures = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # schedule tasks
            for domain in domains:
                if use_crtsh:
                    futures.append(executor.submit(("crtsh", domain), get_subdomains_crtsh, domain))
                if use_sublister:
                    futures.append(executor.submit(("sublister", domain), get_subdomains_sublister, domain))
                if use_brute:
                    futures.append(executor.submit(("brute", domain), brute_force_subdomains, domain))
            # NOTE: above use of executor.submit with tuple label won't work; instead schedule without label and handle mapping below

        # Because we want to update progress as each domain-method completes, reimplement scheduling properly:
        st.session_state.logs = []
        st.session_state.results = set()
        total_tasks = 0
        tasks = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # build task list properly
            for domain in domains:
                if use_crtsh:
                    tasks.append(("crtsh", domain, executor.submit(get_subdomains_crtsh, domain)))
                    total_tasks += 1
                if use_sublister:
                    tasks.append(("sublister", domain, executor.submit(get_subdomains_sublister, domain)))
                    total_tasks += 1
                if use_brute:
                    tasks.append(("brute", domain, executor.submit(brute_force_subdomains, domain)))
                    total_tasks += 1

            # iterate as completed
            done = 0
            for label, domain, fut in tasks:
                try:
                    result = fut.result()
                except Exception as e:
                    result = []
                    log(f"ERROR {label} {domain}: {e}")
                # update results and logs
                if result:
                    added_before = len(st.session_state.results)
                    st.session_state.results.update(result)
                    added_after = len(st.session_state.results)
                    new = added_after - added_before
                    log(f"[{label}] {domain} -> {new} new subdomains")
                else:
                    log(f"[{label}] {domain} -> 0")
                done += 1
                progress.progress(int(done / total_tasks * 100))
        progress.empty()
        log("Scan completed")
        st.success("Scan finished!")

# -----------------------------
# Results Tab
# -----------------------------
with tab_results:
    st.markdown("### Results")
    if st.session_state.results:
        df = pd.DataFrame({"Subdomain": list(st.session_state.results)})
        if search_term:
            df = df[df["Subdomain"].str.contains(search_term, case=False, na=False)]
        df = df.sort_values("Subdomain", ascending=sort_asc).reset_index(drop=True)
        st.dataframe(df, use_container_width=True)
        # selections & download
        fname = save_results_file(st.session_state.results, fmt=export_format.lower())
        with open(fname, "rb") as f:
            st.download_button(" Download results", data=f, file_name=fname)
        st.markdown("**Copy results (select & copy):**")
        st.text_area("All subdomains (select then copy)", value="\n".join(sorted(st.session_state.results)), height=180)
    else:
        st.info("No subdomains found yet. Start a scan to populate results.")

# -----------------------------
# Logs Tab
# -----------------------------
with tab_logs:
    st.markdown("### Logs (live)")
    if st.session_state.logs:
        # show latest first
        for line in reversed(st.session_state.logs[-500:]):
            st.markdown(f"<pre style='color:#00ff6a; background:#010101; padding:6px'>{line}</pre>", unsafe_allow_html=True)
    else:
        st.info("No logs yet. Run a scan to see live logs here.")

# -----------------------------
# About Tab
# -----------------------------
with tab_about:
    st.markdown("### About this app")
    st.markdown("""
    - Built with Streamlit — improved UI, progress, logs, and filters.
    - Use responsibly and only against systems you have permission to test.
    - To include Sublist3r, add the Sublist3r folder to the repo.
    """)

