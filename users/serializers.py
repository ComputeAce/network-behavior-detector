from rest_framework import serializers
from django.contrib.auth.models import User

class UserRegistrationSelizer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        # Check if password and password2 match
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields did not match."})
        return attrs

    def create(self, validated_data):
        # Remove password2 from validated_data as it is not a field in the User model
        validated_data.pop('password2')
        user = User.objects.create_user(
            username=validated_data['username'],
            #email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    


