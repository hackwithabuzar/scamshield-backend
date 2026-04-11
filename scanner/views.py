import re
import zipfile
import os
from rest_framework.decorators import api_view
from rest_framework.response import Response
import requests
import base64
import hashlib

VT_API_KEY = os.environ.get("VT_API_KEY")

# 🔥 METRICS
total_checks = 0
safe_count = 0
warning_count = 0
danger_count = 0
total_score = 0
high_risk_count = 0


# =========================
# VIRUSTOTAL URL
# =========================
def check_url_vt(url):
    try:
        if not VT_API_KEY:
            return None

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(vt_url, headers=headers, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()

        if "data" not in data:
            return None

        attributes = data["data"].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return stats.get("malicious", 0), stats.get("suspicious", 0)

    except Exception as e:
        print("VT URL ERROR:", e)
        return None


# =========================
# URL ANALYSIS
# =========================
def analyze_url(url):
    score = 100
    reasons = []
    url = url.lower()

    if url.startswith("http://"):
        score -= 20
        reasons.append("No HTTPS")

    if re.search(r'login|verify|bank|secure|update|account|payment|free|offer|bonus|win', url):
        score -= 25
        reasons.append("Phishing keywords")

    if "@" in url:
        score -= 15
        reasons.append("Suspicious '@'")

    if url.count('.') > 3:
        score -= 10
        reasons.append("Too many subdomains")

    if len(url) > 60:
        score -= 10
        reasons.append("Very long URL")

    return score, reasons


# =========================
# URL API
# =========================
@api_view(['GET'])
def check_url(request):
    global total_checks, safe_count, warning_count, danger_count, total_score, high_risk_count

    try:
        url = request.GET.get('url')

        if not url:
            return Response({"error": "No URL provided"})

        score, reasons = analyze_url(url)

        # 🔥 SAFE VT
        vt_result = check_url_vt(url)

        if vt_result:
            malicious, suspicious = vt_result

            if malicious > 0:
                score -= 40
                reasons.append(f"{malicious} engines flagged")

            if suspicious > 0:
                score -= 20
                reasons.append(f"{suspicious} suspicious engines")
        else:
            reasons.append("VT unavailable")

        score = max(0, min(score, 100))

        status = "SAFE" if score > 80 else "WARNING" if score > 50 else "DANGEROUS"

        # 🔥 METRICS
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

    except Exception as e:
        print("ERROR check_url:", e)
        return Response({
            "error": "Server error",
            "details": str(e)
        })


# =========================
# APK HASH
# =========================
def get_file_hash(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# =========================
# VIRUSTOTAL APK
# =========================
def check_apk_vt(file_hash):
    try:
        if not VT_API_KEY:
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            return None

        data = response.json()

        if "data" not in data:
            return None

        attributes = data["data"].get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return stats.get("malicious", 0), stats.get("suspicious", 0)

    except Exception as e:
        print("VT APK ERROR:", e)
        return None


# =========================
# APK ANALYSIS
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

    except Exception as e:
        print("APK ERROR:", e)
        reasons.append("APK analysis error")

    score = max(0, min(score, 100))

    risk = "LOW" if score > 80 else "MEDIUM" if score > 50 else "HIGH"

    return score, reasons, risk


# =========================
# APK API
# =========================
@api_view(['GET', 'POST'])
def upload_apk(request):
    global total_checks, safe_count, warning_count, danger_count, total_score, high_risk_count

    try:
        if request.method == "GET":
            return Response({"message": "Use POST"})

        file = request.FILES.get('apk')

        if not file:
            return Response({"error": "No file uploaded"})

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        path = os.path.join(UPLOAD_DIR, file.name)

        with open(path, "wb+") as f:
            for chunk in file.chunks():
                f.write(chunk)

        score, reasons, risk = analyze_apk(path)

        # 🔥 SAFE VT
        vt_result = check_apk_vt(get_file_hash(path))

        if vt_result:
            malicious, suspicious = vt_result

            if malicious > 0:
                score -= 40
                reasons.append("Malicious detected")
        else:
            reasons.append("VT unavailable")

        os.remove(path)

        score = max(0, min(score, 100))

        status = "SAFE" if score > 80 else "WARNING" if score > 50 else "DANGEROUS"

        # 🔥 METRICS
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

    except Exception as e:
        print("ERROR upload_apk:", e)
        return Response({
            "error": "Server error",
            "details": str(e)
        })


# =========================
# METRICS API
# =========================
@api_view(['GET'])
def metrics(request):
    avg = total_score / total_checks if total_checks else 0

    return Response({
        "total_checks": total_checks,
        "safe": safe_count,
        "warning": warning_count,
        "dangerous": danger_count,
        "average_score": round(avg, 2)
    })