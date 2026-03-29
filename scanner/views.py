import re
import zipfile
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


# APK ANALYSIS ENGINE
def analyze_apk(path):
    score = 100
    reasons = []

    try:
        with zipfile.ZipFile(path, 'r') as apk:
            files = apk.namelist()

            for f in files:
                if "sms" in f.lower():
                    score -= 20
                    reasons.append("Uses SMS functionality")

                if "http" in f.lower():
                    score -= 10
                    reasons.append("Contains network calls")

                if "dex" in f.lower():
                    reasons.append("Contains DEX file (normal)")

    except:
        reasons.append("Error analyzing APK")

    return score, reasons


# APK UPLOAD API
@csrf_exempt
def upload_apk(request):
    if request.method == "POST":
        file = request.FILES.get('apk')

        if not file:
            return Response({"error": "No file uploaded"})

        path = "uploads/" + file.name

        with open(path, "wb+") as f:
            for chunk in file.chunks():
                f.write(chunk)

        score, reasons = analyze_apk(path)

        if score > 80:
            status = "SAFE"
        elif score > 50:
            status = "WARNING"
        else:
            status = "DANGEROUS"

        return Response({
            "file": file.name,
            "score": score,
            "status": status,
            "reasons": reasons
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