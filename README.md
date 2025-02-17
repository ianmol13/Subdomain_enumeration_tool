# Subdomain_enumeration_tool
Subdomain Enumeration Tool

This tool automates subdomain discovery using multiple techniques like crt.sh, Sublist3r, and brute force. It features a sleek, hacker-themed Streamlit dashboard for ease of use.

🚀 Features

Passive & Active Enumeration: Uses APIs and wordlists.

Multi-Domain Scanning: Scan multiple domains simultaneously.

Customizable Export: Download results as CSV or JSON.

User-Friendly Interface: Hacker-themed UI with Streamlit.

⚙️ Installation

# Clone the repository
git clone https://github.com/ianmol13/Subdomain_enumeration_tool.git
cd Subdomain_enumeration_tool

# Install dependencies
pip install -r requirements.txt

🔧 Usage

streamlit run Subdomain_Enumeration_Tool.py

🛠 Techniques Used

API Integration: crt.sh for passive enumeration.

DNS Resolution: Uses dnspython to resolve subdomains.

Threading: Multithreading to enhance performance.

📦 Dependencies

Streamlit: Interactive web interface.

dnspython: DNS queries.

requests: HTTP requests.

pandas: Data handling.
