from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Administradores, Alumnos, Organizadores


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    rol = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "password", "rol")

    def validate(self, data):
        # Ensure username exists (use email as username if missing)
        if not data.get('username') and data.get('email'):
            data['username'] = data.get('email')

        # Validate unique email for creation
        email = data.get('email')
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': ['Este email ya está registrado.']})

        return data

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user


class AdminSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Administradores
        fields = ("id", "user", "clave_admin", "creation", "update", "first_name", "last_name", "email")


class AlumnoSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Alumnos
        fields = ("id", "user", "matricula", "ocupacion", "creation", "update", "first_name", "last_name", "email")


class OrganizadorSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Organizadores
        fields = ("id", "user", "id_trabajador", "creation", "update", "first_name", "last_name", "email")
