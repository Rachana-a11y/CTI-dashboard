from dashboard.api_clients import fetch_virustotal, fetch_abuseipdb, fetch_otx
from dashboard.utils import detect_ioc_type
import random
from django.core.cache import cache

def calculate_score(vt, abuse, otx):
    score = 0

    if vt["malicious"] > 5:
        score += 40

    if abuse.get("abuseConfidenceScore", 0) > 50:
        score += 30

    if otx.get("pulse_count", 0) > 0:
        score += 30

    return score


def get_verdict(score):
    if score > 70:
        return "HIGH RISK"
    elif score > 40:
        return "MEDIUM RISK"
    return "LOW RISK"


def process_ioc(ioc):
    ioc_type = detect_ioc_type(ioc)

    vt = fetch_virustotal(ioc)
    abuse = fetch_abuseipdb(ioc) if ioc_type == "ip" else {}
    otx = fetch_otx(ioc, ioc_type)

    score = calculate_score(vt, abuse, otx)
    verdict = get_verdict(score)

    return {
        "type": ioc_type,
        "vt": vt,
        "abuse": abuse,
        "otx": otx,
        "score": score,
        "verdict": verdict,
        "mitre": []
    }
    
    
def analyze_ioc(ioc, ioc_type):
    cache_key = f"ioc_{ioc}"
    cached = cache.get(cache_key)

    if cached:
        return cached

    score = random.randint(0, 100)

    if score > 70:
        verdict = "malicious"
    elif score > 40:
        verdict = "suspicious"
    else:
        verdict = "harmless"

    result = {
        "score": score,
        "verdict": verdict,
        "source": "AI Engine",
        "link": f"https://intel.report/{ioc}"
    }

    cache.set(cache_key, result, timeout=3600)
    return result