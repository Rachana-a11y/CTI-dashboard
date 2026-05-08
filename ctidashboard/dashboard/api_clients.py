import requests
from django.conf import settings


HEADERS_VT = {"x-apikey": settings.VT_API_KEY}
HEADERS_OTX = {"X-OTX-API-KEY": settings.MITRE_OTX_API_KEY}
HEADERS_ABUSE = {"Key": settings.ABUSEIPDB_API_KEY}
HEADERS_ST = {"apikey": settings.SECURITY_TRAILS_API}


# 🔹 VirusTotal
def fetch_virustotal(ioc):
    try:
        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
        res = requests.get(url, headers=HEADERS_VT, timeout=10)
        data = res.json()

        stats = data.get("data", [{}])[0].get("attributes", {}).get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "link": f"https://www.virustotal.com/gui/search/{ioc}"
        }

    except:
        return {"malicious": 0}


# 🔹 OTX
def fetch_otx(ioc, ioc_type):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
        res = requests.get(url, headers=HEADERS_OTX, timeout=10)
        data = res.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])

        return {
            "pulse_count": len(pulses),
            "link": f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc}"
        }

    except:
        return {"pulse_count": 0}


# 🔹 AbuseIPDB
def fetch_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip}

        res = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=10)
        data = res.json().get("data", {})

        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"),
            "link": f"https://abuseipdb.com/check/{ip}"
        }

    except:
        return {"abuseConfidenceScore": 0}


# 🔹 Subdomains
def fetch_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=10)

        subs = set()
        for entry in res.json():
            for sub in entry.get("name_value", "").split("\n"):
                subs.add(sub.strip())

        return list(subs)

    except:
        return []


def fetch_securitytrails(domain):
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        res = requests.get(url, headers=HEADERS_ST, timeout=10)

        subs = res.json().get("subdomains", [])
        return [f"{s}.{domain}" for s in subs]

    except:
        return []