import csv
import json
import os 
import time 
import ipaddress 
import requests 

fileIn = "ps_remote_ips.json"
csvOut = "ip_report.csv"

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not API_KEY:
    raise SystemExit("Missing ABUSEIPDB_API_KEY environment variable. Set it in PowerShell first.")

# Public Ip checker
def public_ip_checker(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False #invalid ips treated as non public
    

# reading the JSON file
with open(fileIn, "r", encoding="utf-8-sig") as f:
    data = json.load(f)

ips = []
seen = set()
#strips remote ips as needed
for c in data.get("Connections", []):
    ip = str(c.get("RemoteIP", "")).strip()
    if ip and ip not in seen:
        seen.add(ip)
        ips.append(ip)

threshold = 25
max_age = 100
rows = []
flagged = 0
for ip in ips:
    if not public_ip_checker(ip):
        continue
    try:# API request
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": str(max_age)},
            timeout=15,
        )
        r.raise_for_status
        d = r.json().get("data", {}) or {} #File parsinh
        score = int(d.get("abuseConfidenceScore") or 0)
        is_bad = score >= threshold
        if is_bad:
            flagged = flagged + 1
        
        rows.append({
            "ip": ip,
            "abuse_score": score,
            "total_reports": d.get("totalReports"),
            "country": d.get("countryCode"),
            "flagged": is_bad,
        })
        time.sleep(1)
    except Exception as e:# Captures erros as well
        rows.append({
            "ip": ip,
            "abuse_score": "",
            "total_reports": "",
            "country": "",
            "flagged": False,
            "error": str(e),
        })

# Report csv style
fieldnames = ["ip", "abuse_score", "total_reports", "country", "flagged", "error"]
with open(csvOut, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)
#Simmary of console
print(f"Unique IPs found: {len(ips)}")
print(f"Checked public IPs: {len(rows)}")
print(f"Flagged (score >= {threshold}): {flagged}")
print(f"Wrote: {csvOut}")