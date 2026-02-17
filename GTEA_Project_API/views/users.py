from django.shortcuts import render
from django.db.models import *
from django.db import transaction
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
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import JSONParser
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


class AdminAll(generics.CreateAPIView):
    #Esta linea se usa para pedir el token de autenticación de inicio de sesión
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        admin = Administradores.objects.filter(user__is_active = 1).order_by("id")
        lista = AdminSerializer(admin, many=True).data
        
        return Response(lista, 200)


class AdminView(generics.CreateAPIView):
    #Obtener usuario por ID
    # permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserSerializer

    def get_serializer_class(self):
        # Use AdminSerializer for GET (representation) and UserSerializer for POST (creation)
        if hasattr(self, 'request') and self.request.method == 'GET':
            return AdminSerializer
        return self.serializer_class
    def get(self, request, *args, **kwargs):
        admin = get_object_or_404(Administradores, id = request.GET.get("id"))
        admin = AdminSerializer(admin, many=False).data

        return Response(admin, 200)
    
    #Registrar nuevo usuario
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        # Work on a mutable copy of the incoming data so we can ensure username exists
        payload = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        if not payload.get('username') and payload.get('email'):
            payload['username'] = payload.get('email')

        user = UserSerializer(data=payload)
        if user.is_valid():
            # Grab user data from payload (use get() to avoid KeyError)
            role = payload.get('rol')
            first_name = payload.get('first_name')
            last_name = payload.get('last_name')
            email = payload.get('email')
            password = payload.get('password')

            # Valida si existe el usuario o bien el email registrado
            existing_user = User.objects.filter(email=email).first()

            if existing_user:
                return Response({"email": [f"Username {email} is already taken"]}, status=400)

            user = User.objects.create(username=email,
                                       email=email,
                                       first_name=first_name or '',
                                       last_name=last_name or '',
                                       is_active=1)

            user.save()
            if password:
                user.set_password(password)
                user.save()

            group, created = Group.objects.get_or_create(name=role)
            group.user_set.add(user)
            user.save()

            # Create a profile for the user
            admin = Administradores.objects.create(user=user,
                                                   clave_admin=payload.get("clave_admin"))
            admin.save()

            return Response({"admin_created_id": admin.id}, 201)

        return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminsViewEdit(generics.CreateAPIView):
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

        return Response({'admins': total_admins, 'organizadores': total_organizadores, 'alumnos:':total_alumnos }, 200)
    
    #Editar administrador
    def put(self, request, *args, **kwargs):
        # iduser=request.data["id"]
        admin = get_object_or_404(Administradores, id=request.data["id"])
        admin.clave_admin = request.data.get("clave_admin", admin.clave_admin)
        admin.save()
        temp = admin.user
        temp.first_name = request.data["first_name"]
        temp.last_name = request.data["last_name"]
        temp.save()
        user = AdminSerializer(admin, many=False).data

        return Response(user,200)

    def delete(serlf, request, *args, **kwargs):
        admin= get_object_or_404(Administradores, id=request.GET.get("id"))
        try:
            admin.user.delete()
            return Response({"details": "Administrador eliminado"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})


# --- register_user endpoint (minimal, for debugging incoming payloads) ---
@api_view(['POST'])
@parser_classes([JSONParser])
def register_user(request):
    """Register a user and log incoming request payloads for debugging."""
    logger.info("RAW BODY: %s", request.body)
    logger.info("PARSED DATA: %s", request.data)
    logger.info("REQUEST.POST: %s", request.POST)

    username = request.data.get('username') or request.data.get('email') or request.POST.get('username')
    password = request.data.get('password') or request.POST.get('password')

    if not username or not password:
        return Response({'detail': 'username and password required'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'detail': 'user already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, password=password)
    return Response({'id': user.id, 'username': user.username}, status=status.HTTP_201_CREATED)
