import requests
from depwatch import config
import json

url = "https://api.github.com/advisories"
headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {config.github_token()}"
}
params = {
    "per_page": 5,          # results per page (max 100, default 30)
    "sort": "updated",      # updated | published | epss_percentage | epss_percentile
    "direction": "desc",    # asc | desc  (desc = newest first)
    "type": "reviewed",     # reviewed | unreviewed | malware  (reviewed = curated)
    # --- optional filters, uncomment to experiment ---
    # "ecosystem": "pip",           # pip | npm | maven | go | rubygems | nuget | composer | ...
    # "severity": "high",           # low | medium | high | critical
    # "updated": ">=2026-07-01",    # date/range filter — this becomes our watermark later
}

r = requests.get(url,headers=headers, params= params)
print(r.json()[0]['description'])

adv = r.json()[0]
print("rate limit  :", r.headers.get("X-RateLimit-Remaining"), "/", r.headers.get("X-RateLimit-Limit"))
print(json.dumps(adv["vulnerabilities"], indent=2 )[:1200])
