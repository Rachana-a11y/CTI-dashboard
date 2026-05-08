# core/analyzer.py

def analyze_ioc(data):
    score = 0
    
    if data["virustotal"]["malicious"] > 5:
        score += 40
        
    if data["abuseipdb"]["abuseConfidenceScore"] > 50:
        score += 30
        
    if data["otx"]["pulse_count"] > 0:
        score += 30

    if score > 70:
        verdict = "HIGH RISK"
    elif score > 40:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return {
        "score": score,
        "verdict": verdict
    }