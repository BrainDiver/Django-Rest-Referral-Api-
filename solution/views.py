from django.shortcuts import render, redirect
from django.conf import settings
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import login

from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from jose import jwt, jwe

import time
from datetime import datetime
from datetime import timedelta

from .models import User
from .serializers import (
    Login_Serializer,
    SMS_Verification_Serializer,
    Profile_Serializer,
)

# Create your views here.
class LoginAPIView(generics.GenericAPIView):
    serializer_class = Login_Serializer
    template_name = "solution/login.html"

    def get(self, request):
        type = request.headers.get("application")
        if type == "application":
            serializer = self.serializer_class()
            return Response(serializer.data)
        else:
            return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        data = {}
        content_type = request.headers.get("content_type").split(";")[0]
        if content_type == "multipart/form-data" or content_type == "application/json":
            if serializer.is_valid():
                data = serializer.data
                sms_token = self.get_sms_token(data)
                request.session["sms_token"] = sms_token.decode(
                    "utf-8"
                )  # Временное решение. Если в следующем запросе не будет введен sms_token то программа возмет его с request.session
                return Response(
                    data={
                        "sms_token": sms_token,
                        "url_to_confirm": request.build_absolute_uri("/")
                        + "solution/sms_verification/",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                data = serializer.errors
                return Response(data)
        else:
            if serializer.is_valid():
                data = serializer.data
                sms_token = self.get_sms_token(data)
                request.session["sms_token"] = sms_token.decode("utf-8")
                return redirect(reverse("sms_verification"))
            else:
                return render(request, self.template_name, context={})

    @staticmethod
    def get_sms_token(data):
        time.sleep(2)  # Задержка
        sms_code = "0000"  # Код

        payload = {
            "credentials": dict(data),
            "sent_sms_code": sms_code,
        }

        token = jwt.encode(payload, "")
        encrypted_token = jwe.encrypt(
            token.encode("utf-8"), key=settings.JWE_SECRET, encryption="A256CBC-HS512"
        )
        return encrypted_token


class SMS_VerificationAPIView(generics.GenericAPIView, MiddlewareMixin, BaseBackend):
    serializer_class = SMS_Verification_Serializer
    #    renderer_classes = [TemplateHTMLRenderer]
    template_name = "solution/sms_verification.html"

    def get(self, request):
        type = request.headers.get("application")
        if type == "application":
            serializer = self.serializer_class()
            return Response(serializer.data)
        else:
            return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"session": request.session.get("sms_token")}
        )
        data = {}
        content_type = request.headers.get("content_type").split(";")[0]

        if content_type == "multipart/form-data" or content_type == "application/json":

            if serializer.is_valid(raise_exception=True):
                user_sms_code = serializer.data.get("sms_code")
                sms_token = serializer.data.get("sms_token") or request.session.get(
                    "sms_token"
                )
                token = self.decrypt_token(sms_token)
                payload = self.decode_token(token, key="")
                if payload.get("sent_sms_code") != user_sms_code:
                    raise HttpException(
                        "Invalid SMS code", status_code=status.HTTP_401_UNAUTHORIZED
                    )
                else:
                    user = User.get_or_create_user(payload.get("credentials"))

                    try:
                        token = Token.objects.create(user=user)
                    except:
                        token = Token.objects.get(user_id=user)
                    user = self.authenticate(request, token)
                    return Response(
                        {
                            "message": "Authenticated",
                            "auth_token": token.key,
                            "profile_url": request.build_absolute_uri("/")
                            + "solution/profile/",
                        }
                    )
            else:
                data = serializer.errors
                return Response(data)

        else:

            if serializer.is_valid(raise_exception=True):
                user_sms_code = serializer.data.get("sms_code")
                sms_token = serializer.data.get("sms_token") or request.session.get(
                    "sms_token"
                )
                token = self.decrypt_token(sms_token)
                payload = self.decode_token(token, key="")
                if payload.get("sent_sms_code") != user_sms_code:
                    raise HttpException(
                        "Invalid SMS code", status_code=status.HTTP_401_UNAUTHORIZED
                    )
                else:
                    user = User.get_or_create_user(payload.get("credentials"))
                    try:
                        token = Token.objects.create(user=user)
                    except:
                        token = Token.objects.get(user_id=user)

                user = self.authenticate(request, token)
                return redirect("profile")
            else:
                return render(request, template_name, context={})

    def authenticate(self, request, token):
        user = None

        try:
            user = Token.objects.get(key=token.key).user
        except:
            pass
        if user != None:
            login(request, user)
            return user
        else:
            return

    @staticmethod
    def decrypt_token(token) -> str:
        try:
            return jwe.decrypt(token, settings.JWE_SECRET).decode()
        except (jose.exceptions.JWEError, jose.exceptions.JWEParseError):
            raise HttpException("Invalid token")

    @staticmethod
    def decode_token(token, *args, **kwargs) -> dict:
        try:
            return jwt.decode(token, *args, **kwargs)
        except jose.exceptions.JWTError:
            raise HttpException("Invalid token")


class ProfileRetrieveAPIView(generics.GenericAPIView):
    serializer_class = Profile_Serializer
    # renderer_classes = [TemplateHTMLRenderer]
    template_name = "solution/profile.html"

    def get(self, request, **kwargs):
        serializer = self.serializer_class
        type = request.headers.get("application")
        if type == "application":
            try:
                profile = User.objects.get(phone_number=str(request.user))
                data = {"profile": serializer(profile).data}
                return Response(data)
            except Exception as error:
                profile = "Такого профиля не существует"
                data = {"profile": profile}
                return Response(data)
        else:
            return render(
                request, self.template_name, context={"profile": request.user}
            )

    def post(self, request, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        data = {}
        content_type = request.headers.get("content_type").split(";")[0]
        if content_type == "multipart/form-data" or content_type == "application/json":

            if serializer.is_valid(raise_exception=True):
                try:
                    profile = User.objects.get(phone_number=str(request.user))
                    profile.referal_user = User.objects.get(
                        referal_code=serializer.data.get("referal_user")
                    )
                    profile.save()
                    return Response(
                        data={
                            "profile": {
                                "phone_number": profile.phone_number.as_e164,
                                "referal_code": profile.referal_code,
                                "referal_user": profile.referal_user.username,
                                "invited_users": profile.get_invited_users,
                            }
                        },
                        status=status.HTTP_200_OK,
                    )
                except:
                    try:
                        profile = User.objects.get(phone_number=str(request.user))
                        return Response(
                            data={
                                "profile": {
                                    "phone_number": profile.phone_number.as_e164,
                                    "referal_code": profile.referal_code,
                                    "referal_user": profile.referal_user.username,
                                    "invited_users": profile.get_invited_users,
                                }
                            },
                            status=status.HTTP_200_OK,
                        )
                    except:
                        return Response(data = {"profile": "no such profile"})
        else:
            referal_user = request.POST.get('referal_user')
            try:
                profile = User.objects.get(phone_number = str(request.user))
                profile.referal_user = User.objects.get(referal_code = referal_user)
                profile.save
            except:
                pass
            return redirect(reverse('profile'))
