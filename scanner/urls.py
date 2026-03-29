from django.urls import path
from .views import check_url, upload_apk, metrics

urlpatterns = [
    path('check-url/', check_url),
    path('upload-apk/', upload_apk),
    path('metrics/', metrics),
]