import re
import zipfile
import os
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt

#  URL ANALYSIS ENGINE
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

#  URL CHECK API
@api_view(['GET'])
def check_url(request):
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

    return Response({
        "url": url,
        "score": score,
        "status": status,
        "reasons": reasons
    })


UPLOAD_DIR = "uploads/"

def analyze_apk(path):
    score = 100
    reasons = []

    # NEW: details dictionary
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

    except:
        reasons.append("Error analyzing APK")

    # Clamp score
    score = max(0, min(score, 100))

    # NEW: risk category
    if score > 80:
        risk = "LOW"
    elif score > 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, reasons, risk, details

#  APK UPLOAD API
@csrf_exempt
def upload_apk(request):
    
    # HANDLE GET (IMPORTANT FIX)
    if request.method == "GET":
        return Response({"message": "Send APK file using POST request"})

    #  HANDLE POST (YOUR MAIN LOGIC)
    if request.method == "POST":
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

        # Status logic
        if score > 80:
            status = "SAFE"
        elif score > 50:
            status = "WARNING"
        else:
            status = "DANGEROUS"

        # DELETE FILE AFTER ANALYSIS (IMPORTANT)
        os.remove(path)

        return Response({
           "file": file.name,
           "score": score,
           "status": status,
           "risk": risk,
           "reasons": reasons,
           "details": details
        })


# METRICS API (ADVANCED)
@api_view(['GET'])
def metrics(request):
    return Response({
        "total_checks": 150,
        "safe": 80,
        "warning": 40,
        "dangerous": 30
    })