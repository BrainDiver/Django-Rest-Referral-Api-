from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import AbstractUser

# from django.contrib.auth.backends import BaseBackend
import secrets


class User(AbstractUser):
    phone_number = PhoneNumberField(max_length=32, verbose_name="Телефон", unique=True)
    referal_code = models.CharField(max_length=6)
    referal_user = models.ForeignKey(
        "self", on_delete=models.DO_NOTHING, null=True, blank=True
    )

    def __str__(self):
        return str(self.phone_number)

    def create_referal_code(self):
        while referal_code := secrets.token_hex(3):
            if User.objects.filter(referal_code=referal_code).exists():
                continue
            self.referal_code = referal_code
            break

    @classmethod
    def create_user(cls, data: dict):
        user = cls(**data)
        user.create_referal_code()
        user.save()
        return user

    @classmethod
    def get_or_create_user(cls, data):
        phone = data.get("phone_number")
        data = data
        data["username"] = phone
        user = cls.objects.filter(phone_number=phone).first()
        if not user:
            user = cls.create_user(data)
        return user

    def to_as_e164(self, number):
        number = number.as_e164
        return number

    @property
    def get_invited_users(self):
        numbers = User.objects.filter(referal_user_id=self.id).values_list(
            "phone_number", flat=True
        )
        numbers = list(map(self.to_as_e164, numbers))
        return numbers
