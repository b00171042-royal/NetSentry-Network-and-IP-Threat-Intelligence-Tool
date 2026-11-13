How the Project works
A PowerShell script captures active TCP connections and retrieves external IP addresses.
The collected data is saved in JSON and CSV formats.
A Python script reads the JSON file, deletes duplicate and private IP addresses, and queries AbuseIPDB.
The results are written to a final CSV report that shows whether any IP addresses are potentially malicious.
Install Python and add it to PATH
In powershell
python -m pip install requests
.\collect_remote_ips.ps1
python .\ip_check_simple.py
