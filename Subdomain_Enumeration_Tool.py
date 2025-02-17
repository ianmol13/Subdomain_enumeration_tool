import streamlit as st
import requests
import dns.resolver
import subprocess
import json
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

# Set Streamlit Page Config
st.set_page_config(page_title="Subdomain Enumeration Tool", page_icon="🔍", layout="wide")

# Custom CSS for better UI
def load_css():
    st.markdown("""
        <style>
            .main {background-color: #f4f4f4;}
            .stButton>button {background-color: #ff4b4b; color: white; font-weight: bold; padding: 10px 24px;}
            .stButton>button:hover {background-color: #ff0000;}
        </style>
    """, unsafe_allow_html=True)

load_css()

# Fetch subdomains from crt.sh
def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return []
        data = response.json()
        return list(set(entry["name_value"] for entry in data))
    except:
        return []

# Run Sublist3r (Passive Enumeration)
def get_subdomains_sublister(domain):
    try:
        result = subprocess.run(["python", "Sublist3r/sublist3r.py", "-d", domain, "-o", "subdomains.txt"], 
                                capture_output=True, text=True)
        return result.stdout.split("\n")
    except Exception as e:
        return []

# Brute-force subdomains using a wordlist
def brute_force_subdomains(domain, wordlist="common_subdomains.txt"):
    subdomains = []
    resolver = dns.resolver.Resolver()

    try:
        with open(wordlist, "r") as file:
            for sub in file:
                full_domain = f"{sub.strip()}.{domain}"
                try:
                    resolver.resolve(full_domain, "A")
                    subdomains.append(full_domain)
                except dns.resolver.NXDOMAIN:
                    pass
    except FileNotFoundError:
        st.error("Wordlist file not found. Please add 'common_subdomains.txt'.")
    
    return subdomains

# Save results
def save_results(subdomains, format="csv"):
    df = pd.DataFrame({"Subdomains": list(subdomains)})
    file_path = f"subdomains_found.{format}"
    df.to_csv(file_path, index=False) if format == "csv" else df.to_json(file_path, orient="records")
    return file_path

# Web Dashboard UI
st.markdown("""
    <h1 style='text-align: center;'>🔍 Automated Subdomain Enumeration Tool</h1>
    <p style='text-align: center; font-size: 18px;'>Discover subdomains with multiple techniques & export results.</p>
""", unsafe_allow_html=True)

st.sidebar.header("⚙️ Settings")
domains = st.sidebar.text_area("🔹 Enter target domains (one per line)").split("\n")
use_crtsh = st.sidebar.checkbox("🛠 Use crt.sh", value=True)
use_sublister = st.sidebar.checkbox("🛠 Use Sublist3r", value=False)
use_brute = st.sidebar.checkbox("🛠 Use Brute Force", value=False)
export_format = st.sidebar.selectbox("💾 Export Results As", ["CSV", "JSON"])
run_scan = st.sidebar.button("🚀 Start Scan")

if run_scan and domains:
    st.subheader("🔄 Scanning in Progress... Please wait.")
    results = set()
    with ThreadPoolExecutor(max_workers=3) as executor:
        tasks = []
        for domain in domains:
            if use_crtsh:
                tasks.append(executor.submit(get_subdomains_crtsh, domain))
            if use_sublister:
                tasks.append(executor.submit(get_subdomains_sublister, domain))
            if use_brute:
                tasks.append(executor.submit(brute_force_subdomains, domain))

        for task in tasks:
            results.update(task.result())

    if results:
        st.success(f"✅ Found {len(results)} subdomains!")
        st.dataframe(pd.DataFrame({"Subdomains": list(results)}))
        
        file_path = save_results(results, export_format.lower())
        st.download_button(label=f"📥 Download {export_format}", data=open(file_path, "rb"), file_name=file_path)
    else:
        st.warning("❌ No subdomains found.")
