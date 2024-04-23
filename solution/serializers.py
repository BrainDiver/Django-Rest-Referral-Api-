from rest_framework import serializers
from phonenumber_field.serializerfields import PhoneNumberField
from .models import User

#Create your serializers here
class Login_Serializer(serializers.Serializer):
    phone_number = PhoneNumberField()


class SMS_Verification_Serializer(serializers.Serializer):

    sms_token = serializers.CharField(required = False)
    sms_code = serializers.CharField(initial = "0000", max_length = 4, min_length = 4)
 
    
class Profile_Serializer(serializers.Serializer):


    phone_number = PhoneNumberField(read_only = True)
    referal_code = serializers.CharField(read_only = True)
    referal_user = serializers.CharField()
    invited_users = serializers.SerializerMethodField(read_only = True)


    def validate_referal_user(self, data):
        try:
            user = User.objects.get(referal_code = data)
        except:
            raise serializers.ValidationError("nea")
        return data

    
    def get_invited_users(self, obj):
        if isinstance(obj, dict):
            user = self.context.get('request').user
            return user.get_invited_users
        else:
            return obj.get_invited_users
