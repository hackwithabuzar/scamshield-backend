import re
import zipfile
import os
from rest_framework.decorators import api_view
from rest_framework.response import Response
import requests
import base64
import hashlib

VT_API_KEY = os.environ.get("VT_API_KEY")

# 🔥 METRICS COUNTERS
total_checks = 0
safe_count = 0
warning_count = 0
danger_count = 0
total_score = 0
high_risk_count = 0

# =========================
# VIRUSTOTAL URL CHECK
# =========================
def check_url_vt(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(vt_url, headers=headers, timeout=5)

        if response.status_code != 200:
            return None

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return stats["malicious"], stats["suspicious"]

    except:
        return None


# =========================
# URL ANALYSIS ENGINE
# =========================
def analyze_url(url):
    score = 100
    reasons = []
    url_lower = url.lower()

    if url_lower.startswith("http://"):
        score -= 20
        reasons.append("No HTTPS")

    if re.search(r'login|verify|bank|secure|update|account|payment|free|offer|bonus|win', url_lower):
        score -= 25
        reasons.append("Phishing keywords detected")

    if "@" in url_lower:
        score -= 15
        reasons.append("Suspicious '@' symbol")

    if url_lower.count('.') > 3:
        score -= 10
        reasons.append("Too many subdomains")

    if len(url) > 60:
        score -= 10
        reasons.append("Very long URL")

    if any(char.isdigit() for char in url_lower):
        score -= 10
        reasons.append("Numeric domain detected")

    if url_lower.count('-') > 2:
        score -= 10
        reasons.append("Too many '-' symbols")

    return score, reasons


# =========================
# URL CHECK API
# =========================
@api_view(['GET'])
def check_url(request):
    global total_checks, safe_count, warning_count, danger_count, total_score, high_risk_count

    url = request.GET.get('url')

    if not url:
        return Response({"error": "No URL provided"})

    # 🔥 Step 1: Local Analysis
    score, reasons = analyze_url(url)

    # 🔥 Step 2: VirusTotal (optional)
    vt_result = check_url_vt(url)

    if vt_result:
        malicious, suspicious = vt_result

        if malicious > 0:
            score -= 40
            reasons.append(f"{malicious} engines flagged malicious")

        if suspicious > 0:
            score -= 20
            reasons.append(f"{suspicious} engines suspicious")
    else:
        reasons.append("VT unavailable (using local analysis)")

    # Clamp score
    score = max(0, min(score, 100))

    # Status
    if score > 80:
        status = "SAFE"
    elif score > 50:
        status = "WARNING"
    else:
        status = "DANGEROUS"

    # Metrics
    total_checks += 1
    total_score += score

    if status == "SAFE":
        safe_count += 1
    elif status == "WARNING":
        warning_count += 1
    else:
        danger_count += 1
        high_risk_count += 1

    return Response({
        "url": url,
        "score": score,
        "status": status,
        "reasons": reasons
    })


# =========================
# APK VT HASH
# =========================
def get_file_hash(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_apk_vt(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code != 200:
            return None

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return stats["malicious"], stats["suspicious"]

    except:
        return None


# =========================
# APK ANALYSIS ENGINE
# =========================
UPLOAD_DIR = "uploads/"


def analyze_apk(path):
    score = 100
    reasons = []

    try:
        with zipfile.ZipFile(path, 'r') as apk:
            files = apk.namelist()

            if len(files) > 1500:
                score -= 10
                reasons.append("Large APK")

            for f in files:
                name = f.lower()

                if "sms" in name:
                    score -= 20
                    reasons.append("SMS usage")

                if "http" in name:
                    score -= 10
                    reasons.append("Network calls")

                if "hack" in name or "mod" in name:
                    score -= 20
                    reasons.append("Suspicious file name")

    except:
        reasons.append("Error analyzing APK")

    score = max(0, min(score, 100))

    if score > 80:
        risk = "LOW"
    elif score > 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, reasons, risk


# =========================
# APK UPLOAD API
# =========================
@api_view(['GET', 'POST'])
def upload_apk(request):
    global total_checks, safe_count, warning_count, danger_count, total_score, high_risk_count

    if request.method == "GET":
        return Response({"message": "Send APK file using POST request"})

    elif request.method == "POST":
        file = request.FILES.get('apk')

        if not file:
            return Response({"error": "No file uploaded"})

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        path = os.path.join(UPLOAD_DIR, file.name)

        with open(path, "wb+") as f:
            for chunk in file.chunks():
                f.write(chunk)

        # 🔥 Local analysis
        score, reasons, risk = analyze_apk(path)

        # 🔥 VirusTotal
        file_hash = get_file_hash(path)
        vt_result = check_apk_vt(file_hash)

        if vt_result:
            malicious, suspicious = vt_result

            if malicious > 0:
                score -= 40
                reasons.append(f"{malicious} engines detected malware")

            if suspicious > 0:
                score -= 20
                reasons.append(f"{suspicious} engines suspicious")
        else:
            reasons.append("VT unavailable (local analysis used)")

        os.remove(path)

        score = max(0, min(score, 100))

        if score > 80:
            status = "SAFE"
        elif score > 50:
            status = "WARNING"
        else:
            status = "DANGEROUS"

        total_checks += 1
        total_score += score

        if status == "SAFE":
            safe_count += 1
        elif status == "WARNING":
            warning_count += 1
        else:
            danger_count += 1
            high_risk_count += 1

        return Response({
            "score": score,
            "status": status,
            "risk": risk,
            "reasons": reasons
        })

    return Response({"error": "Invalid request"})


# =========================
# METRICS API
# =========================
@api_view(['GET'])
def metrics(request):
    avg_score = total_score / total_checks if total_checks else 0
    threat_percentage = (danger_count / total_checks) * 100 if total_checks else 0

    return Response({
        "total_checks": total_checks,
        "safe": safe_count,
        "warning": warning_count,
        "dangerous": danger_count,
        "high_risk": high_risk_count,
        "average_score": round(avg_score, 2),
        "threat_percentage": round(threat_percentage, 2)
    })