# SubScan — Subdomain Enumeration Tool

![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square)
![Streamlit](https://img.shields.io/badge/deployed-streamlit%20cloud-ff4b4b?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

A recon tool for subdomain discovery built for bug bounty and penetration testing. Queries 8 sources in parallel, resolves DNS records, probes live hosts, and scores each result by confidence.

**Live:** `https://subdomainenumerationtool.streamlit.app`

---

I built this because most subdomain tools either hit one source or dump a flat list with no context about what's actually alive. This does the full pipeline — enumerate, validate, enrich, score — in one shot.

---

## Sources

Runs all of these simultaneously and deduplicates results:

crt.sh · HackerTarget · AlienVault OTX · VirusTotal · RapidDNS · BufferOver · Sublist3r · DNS brute-force

---

## What happens after enumeration

- **Wildcard detection** — checks for wildcard DNS before brute-forcing so you don't end up with thousands of false positives
- **DNS enrichment** — resolves A, AAAA, CNAME, MX, NS, TXT for every subdomain
- **HTTP probing** — hits each live host, grabs status code, title, redirect chain, and detects technologies (nginx, Cloudflare, WordPress, AWS, etc.)
- **Confidence score** — each result gets a 0–100 score based on how many sources found it, whether DNS resolves, and whether it responds over HTTP

---

## Setup

```bash
git clone https://github.com/ianmol13/Subdomain_enumeration_tool.git
cd Subdomain_enumeration_tool
pip install -r requirements.txt
streamlit run Subdomain_Enumeration_Tool.py
```


## Stack

Python · dnspython · requests · Streamlit · vanilla HTML/CSS/JS

---

Only scan domains you own or have written permission to test.
