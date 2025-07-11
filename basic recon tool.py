import argparse
import json
import csv
import os
import subprocess
import socket
import requests
import whois
import dns.resolver
import nmap
import shodan
import re
from datetime import datetime

# ============ ARGUMENT PARSER ============
parser = argparse.ArgumentParser(description="Intermediate Recon Toolkit")
parser.add_argument("domain", help="Target domain")
parser.add_argument("--portscan", action="store_true", help="Run port scan and banner grab")
parser.add_argument("--techdetect", action="store_true", help="technology used by website")
parser.add_argument("--shodan", action="store_true", help="Run Shodan lookup")
parser.add_argument("--emails", action="store_true", help="Harvest emails [scraping]")
parser.add_argument("--json", action="store_true", help="Save output as JSON")
args = parser.parse_args()

domain = args.domain
output_data = {"domain": domain}

# ============ SUBDOMAIN ENUM ============
def get_subdomains_crtsh(domain):
    print("[*] Fetching subdomains from crt.sh ...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        data = r.json()
        subdomains = {entry['name_value'] for entry in data}
        return sorted(subdomains)
    except:
        return []

def get_subdomains_sublist3r(domain):
    print("[*] Running Sublist3r ...")
    try:
        subprocess.run(['sublist3r', '-d', domain, '-o', 'sublist_output.txt'], capture_output=True)
        with open('sublist_output.txt', 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

# ============ DNS LOOKUP ============
def get_dns_records(domain):
    records = {}
    for record in ['A', 'NS', 'MX']:
        try:
            answers = dns.resolver.resolve(domain, record)
            records[record] = [str(rdata) for rdata in answers]
        except:
            records[record] = []
    return records

# ============ WHOIS ============
def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except:
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True)
            return result.stdout
        except:
            return "WHOIS lookup failed"

# ============ HTTP HEADERS ============
def get_http_headers(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=10)
        return dict(r.headers)
    except:
        return {}

# ============ ROBOTS.TXT & SITEMAP.XML ============
def get_robots_and_sitemap(domain):
    data = {}
    for path in ['robots.txt', 'sitemap.xml']:
        try:
            url = f"http://{domain}/{path}"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data[path] = r.text.strip()
            else:
                data[path] = "Not found"
        except:
            data[path] = "Unreachable"
    return data

# ============ GEOIP ============
def get_geoip(domain):
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"https://ipinfo.io/{ip}/json")
        return r.json()
    except:
        return {}

# ============ PORT SCAN ============
def port_scan(domain):
    print("[*] Scanning ports using Nmap ...")
    nm = nmap.PortScanner()
    try:
        nm.scan(domain, arguments="-Pn -T4 --script=banner")
        open_ports = {}
        for proto in nm[domain].all_protocols():
            for port in nm[domain][proto]:
                port_data = nm[domain][proto][port]
                open_ports[port] = {
                    "state": port_data.get('state'),
                    "banner": port_data.get('script', {}).get('banner', '')
                }
        return open_ports
    except Exception as e:
        return {"error": str(e)}

# ============ TECH DETECTION ============
def detect_tech(domain):
    print("[*] Running WhatWeb ...")
    try:
        output = subprocess.check_output(['whatweb', domain]).decode()
        return output.strip()
    except:
        return "WhatWeb not installed or failed"

# ============ SHODAN ============
def shodan_lookup(domain):
    print("[*] Performing Shodan lookup ...")
    try:
        ip = socket.gethostbyname(domain)
        SHODAN_API_KEY = "urapi(whywouldishowmine)"
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        return {
            "ip": result.get("ip_str"),
            "org": result.get("org"),
            "os": result.get("os"),
            "ports": result.get("ports"),
            "data": result.get("data")[:3]
        }
    except Exception as e:
        return {"error": str(e)}

# ============ EMAIL HARVESTING ============
def harvest_emails(domain):
    print("[*] Harvesting emails using Bing ...")
    emails = set()
    try:
        for i in range(0, 20, 10):
            query = f'"@{domain}"'
            url = f"https://www.bing.com/search?q={query}&first={i}"
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, headers=headers, timeout=10)
            found = re.findall(r"[a-zA-Z0-9_.+-]+@" + re.escape(domain), r.text)
            emails.update(found)
        return list(emails)
    except:
        return []

# ============ REPORT EXPORT ============
def save_report(data, format="json"):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{domain}_report.{format}"
    if format == "json":
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    else:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            for key, val in data.items():
                writer.writerow([key, json.dumps(val)])
    print(f"\n[+] Report saved to {filename}")

# ============ MAIN ============
def main():
    print(f"\n[*] Starting recon for {domain} at {datetime.now()}\n")

    # Basic Recon
    output_data["Subdomains (crt.sh)"] = get_subdomains_crtsh(domain)
    output_data["Subdomains (Sublist3r)"] = get_subdomains_sublist3r(domain)
    output_data["DNS Records"] = get_dns_records(domain)
    output_data["WHOIS"] = get_whois_info(domain)
    output_data["HTTP Headers"] = get_http_headers(domain)
    output_data["robots.txt & sitemap.xml"] = get_robots_and_sitemap(domain)
    output_data["GeoIP"] = get_geoip(domain)

    # Intermediate Features
    if args.portscan:
        output_data["Port Scan"] = port_scan(domain)

    if args.techdetect:
        output_data["Technology Detection"] = detect_tech(domain)

    if args.shodan:
        output_data["Shodan Info"] = shodan_lookup(domain)

    if args.emails:
        output_data["Emails"] = harvest_emails(domain)

    fmt = "json" if args.json else "csv"
    save_report(output_data, fmt)

if __name__ == "__main__":
    main()




#formatted by chatgpt
