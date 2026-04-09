import re
import zipfile
import os
from rest_framework.decorators import api_view
from rest_framework.response import Response

# 🔥 METRICS COUNTERS
total_checks = 0
safe_count = 0
warning_count = 0
danger_count = 0


# =========================
# URL ANALYSIS ENGINE
# =========================
def analyze_url(url):
    score = 100
    reasons = []

    if url.startswith("http://"):
        score -= 20
        reasons.append("No HTTPS (Not secure)")

    if re.search(r'login|verify|bank|secure|free|offer', url):
        score -= 30
        reasons.append("Phishing or scam keywords detected")

    if "@" in url:
        score -= 15
        reasons.append("Suspicious '@' symbol in URL")

    if url.count('.') > 3:
        score -= 10
        reasons.append("Too many subdomains (suspicious)")

    if len(url) > 60:
        score -= 10
        reasons.append("Very long URL (possible obfuscation)")

    return score, reasons


# =========================
# URL CHECK API
# =========================
@api_view(['GET'])
def check_url(request):
    global total_checks, safe_count, warning_count, danger_count

    url = request.GET.get('url')

    if not url:
        return Response({"error": "No URL provided"})

    score, reasons = analyze_url(url)

    if score > 80:
        status = "SAFE"
    elif score > 50:
        status = "WARNING"
    else:
        status = "DANGEROUS"

    # 🔥 METRICS UPDATE
    total_checks += 1

    if status == "SAFE":
        safe_count += 1
    elif status == "WARNING":
        warning_count += 1
    else:
        danger_count += 1

    return Response({
        "url": url,
        "score": score,
        "status": status,
        "reasons": reasons
    })


# =========================
# APK ANALYSIS ENGINE
# =========================
UPLOAD_DIR = "uploads/"


def analyze_apk(path):
    score = 100
    reasons = []

    details = {
        "sms": False,
        "network": False,
        "native_libs": False,
        "assets": False
    }

    try:
        with zipfile.ZipFile(path, 'r') as apk:
            files = apk.namelist()

            for f in files:
                name = f.lower()

                if "sms" in name:
                    score -= 20
                    reasons.append("Uses SMS functionality")
                    details["sms"] = True

                if "http" in name:
                    score -= 10
                    reasons.append("Contains network calls")
                    details["network"] = True

                if "lib/" in name:
                    details["native_libs"] = True

                if "assets/" in name:
                    details["assets"] = True

    except Exception as e:
        reasons.append("Error analyzing APK")

    # Clamp score
    score = max(0, min(score, 100))

    # Risk level
    if score > 80:
        risk = "LOW"
    elif score > 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, reasons, risk, details


# =========================
# APK UPLOAD API
# =========================
@api_view(['GET', 'POST'])
def upload_apk(request):
    global total_checks, safe_count, warning_count, danger_count

    if request.method == "GET":
        return Response({"message": "Send APK file using POST request"})

    elif request.method == "POST":
        file = request.FILES.get('apk')

        if not file:
            return Response({"error": "No file uploaded"})

        os.makedirs(UPLOAD_DIR, exist_ok=True)

        path = os.path.join(UPLOAD_DIR, file.name)

        # Save file
        with open(path, "wb+") as f:
            for chunk in file.chunks():
                f.write(chunk)

        # Analyze
        score, reasons, risk, details = analyze_apk(path)

        if score > 80:
            status = "SAFE"
        elif score > 50:
            status = "WARNING"
        else:
            status = "DANGEROUS"

        # Delete file after analysis
        os.remove(path)

        # 🔥 METRICS UPDATE
        total_checks += 1

        if status == "SAFE":
            safe_count += 1
        elif status == "WARNING":
            warning_count += 1
        else:
            danger_count += 1

        return Response({
            "file": file.name,
            "score": score,
            "status": status,
            "risk": risk,
            "reasons": reasons,
            "details": details
        })

    return Response({"error": "Invalid request"})


# =========================
# METRICS API
# =========================
@api_view(['GET'])
def metrics(request):
    return Response({
        "total_checks": total_checks,
        "safe": safe_count,
        "warning": warning_count,
        "dangerous": danger_count
    })