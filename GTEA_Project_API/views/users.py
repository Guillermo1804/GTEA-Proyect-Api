from django.shortcuts import render
from django.db.models import *
from django.db import transaction
from ..authentication import DEFAULT_API_AUTH
from ..serializers import *
from ..models import *
from rest_framework.authentication import BasicAuthentication, SessionAuthentication, TokenAuthentication
from rest_framework.generics import CreateAPIView, DestroyAPIView, UpdateAPIView
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse
from rest_framework import viewsets
from django.shortcuts import get_object_or_404
from django.core import serializers
from django.utils.html import strip_tags
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import Group, User
from django.contrib.auth import get_user_model
from django_filters.rest_framework import DjangoFilterBackend
from django_filters import rest_framework as filters
from datetime import datetime
from django.conf import settings
from django.template.loader import render_to_string
import string
import random
import json
import logging

logger = logging.getLogger(__name__)


def _request_user_is_admin(user) -> bool:
    return bool(
        getattr(user, "is_authenticated", False)
        and user.groups.filter(name="administrador").exists()
    )


class AdminAll(generics.CreateAPIView):
    #Esta linea se usa para pedir el token de autenticación de inicio de sesión
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        admin = Administradores.objects.all().order_by("id")
        lista = AdminSerializer(admin, many=True).data
        
        return Response(lista, 200)


class AdminView(generics.CreateAPIView):
    #Obtener usuario por ID
    # permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = DEFAULT_API_AUTH
    def get(self, request, *args, **kwargs):
        admin = get_object_or_404(Administradores, id = request.GET.get("id"))
        admin = AdminSerializer(admin, many=False).data

        return Response(admin, 200)
    
    #Registrar nuevo usuario
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user = UserSerializer(data=request.data)
        if user.is_valid():
            role = request.data['rol']
            first_name = request.data['first_name']
            last_name = request.data['last_name']
            email = request.data['email']
            password = request.data['password']

            existing_user = User.objects.filter(email=email).first()
            if existing_user:
                return Response({"message":"Username "+email+", is already taken"},400)

            user = User.objects.create( username = email,
                                        email = email,
                                        first_name = first_name,
                                        last_name = last_name,
                                        is_active = 1)

            user.save()
            user.set_password(password)
            user.save()

            group, created = Group.objects.get_or_create(name=role)
            group.user_set.add(user)
            user.save()

            admin = Administradores.objects.create(user=user,
                                                   clave_admin=request.data.get("clave_admin"))
            admin.save()

            return Response({"admin_created_id": admin.id }, 201)

        return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminsViewEdit(generics.CreateAPIView):
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    #Contar el total de cada tipo de usuarios
    def get(self, request, *args, **kwargs):
        #Obtener total de admins
        admin = Administradores.objects.filter(user__is_active = 1).order_by("id")
        lista_admins = AdminSerializer(admin, many=True).data
        # Obtienes la cantidad de elementos en la lista
        total_admins = len(lista_admins)

        #Obtener total de organizadores (antes 'maestros')
        organizadores = Organizadores.objects.filter(user__is_active = 1).order_by("id")
        lista_organizadores = OrganizadorSerializer(organizadores, many=True).data
        total_organizadores = len(lista_organizadores)

        #Obtener total de alumnos
        alumnos = Alumnos.objects.filter(user__is_active = 1).order_by("id")
        lista_alumnos = AlumnoSerializer(alumnos, many=True).data
        total_alumnos = len(lista_alumnos)

        return Response({'admins': total_admins, 'organizadores': total_organizadores, 'alumnos': total_alumnos}, 200)
    
    #Editar administrador
    def put(self, request, *args, **kwargs):
        admin_id = request.data.get("id")
        if admin_id is None:
            return Response({"details": "Falta el campo id"}, status=status.HTTP_400_BAD_REQUEST)
        admin = get_object_or_404(Administradores, id=admin_id)
        admin.clave_admin = request.data.get("clave_admin", admin.clave_admin)
        admin.save()
        temp = admin.user
        if "first_name" in request.data:
            temp.first_name = request.data.get("first_name", temp.first_name)
        if "last_name" in request.data:
            temp.last_name = request.data.get("last_name", temp.last_name)
        if password := request.data.get("password"):
            pw = str(password).strip()
            if pw:
                temp.set_password(pw)
        temp.save()
        user = AdminSerializer(admin, many=False).data

        return Response(user,200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        admin= get_object_or_404(Administradores, id=request.GET.get("id"))
        try:
            admin.user.delete()
            return Response({"details": "Administrador eliminado"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})


class AdminIsActivePatch(APIView):
    """PATCH /admins/<pk>/ — solo administradores; body: { is_active: bool }"""
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def patch(self, request, pk, *args, **kwargs):
        if not _request_user_is_admin(request.user):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if "is_active" not in request.data:
            return Response({"detail": "is_active es requerido"}, status=status.HTTP_400_BAD_REQUEST)
        admin = get_object_or_404(Administradores, pk=pk)
        val = request.data.get("is_active")
        if isinstance(val, str):
            admin.user.is_active = val.strip().lower() in ("1", "true", "yes", "on")
        else:
            admin.user.is_active = bool(val)
        admin.user.save(update_fields=["is_active"])
        return Response(AdminSerializer(admin).data, status=status.HTTP_200_OK)


class CambiarRolView(APIView):
    """
    POST /users/<pk>/cambiar-rol/
    Solo administradores. Contrato alineado con registro (nuevo-usuario-modal):
    Body JSON:
      - rol: "administrador" | "organizador" | "alumno"  (también se acepta "admin" → administrador)
    Opcionales según rol (mismos nombres que en alta):
      - clave_admin (administrador)
      - id_trabajador (organizador)
      - matricula, ocupacion (alumno)
    """
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    @transaction.atomic
    def post(self, request, pk, *args, **kwargs):
        if not _request_user_is_admin(request.user):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        rol_raw = request.data.get("rol")
        if not rol_raw:
            return Response({"detail": "rol es requerido"}, status=status.HTTP_400_BAD_REQUEST)
        r = str(rol_raw).strip().lower()
        if r == "admin":
            r = "administrador"
        if r not in ("administrador", "organizador", "alumno"):
            return Response({"detail": "rol inválido"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=pk)
        user.groups.clear()
        group, _ = Group.objects.get_or_create(name=r)
        group.user_set.add(user)

        if r == "administrador":
            Administradores.objects.get_or_create(
                user=user,
                defaults={"clave_admin": request.data.get("clave_admin") or ""},
            )
        elif r == "organizador":
            Organizadores.objects.get_or_create(
                user=user,
                defaults={"id_trabajador": request.data.get("id_trabajador") or ""},
            )
        else:
            Alumnos.objects.get_or_create(
                user=user,
                defaults={
                    "matricula": request.data.get("matricula") or "",
                    "ocupacion": request.data.get("ocupacion") or "",
                },
            )

        return Response({"detail": "ok", "user_id": user.id, "rol": r}, status=status.HTTP_200_OK)
