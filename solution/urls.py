from django.contrib import admin
from django.urls import path
from .views import *
from django.views.generic import RedirectView

urlpatterns = [
    path("", RedirectView.as_view(url="login/", permanent=True)),
    path("login/", LoginAPIView.as_view(), name="login"),
    path(
        "sms_verification/", SMS_VerificationAPIView.as_view(), name="sms_verification"
    ),
    path("profile/", ProfileRetrieveAPIView.as_view(), name="profile"),
]
