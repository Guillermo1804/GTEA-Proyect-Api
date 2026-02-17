from django.shortcuts import render
from django.db.models import *
from django.db import transaction
from GTEA_Project_API.serializers import *
from GTEA_Project_API.models import *
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
from django.contrib.auth.models import Group
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

class AlumnosAll(generics.CreateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        alumnos = Alumnos.objects.filter(user__is_active = 1).order_by("id")
        lista = AlumnoSerializer(alumnos, many=True).data
        
        return Response(lista, 200)

class AlumnosView(generics.CreateAPIView):
    #Obtener usuario por ID
    # permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        alumno = get_object_or_404(Alumnos, id = request.GET.get("id"))
        alumno = AlumnoSerializer(alumno, many=False).data

        return Response(alumno, 200)
    
    #Registrar nuevo usuario
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        # Diagnostic logging
        logger.info('RAW BODY: %s', request.body)
        logger.info('PARSED DATA: %s', request.data)

        user_serializer = UserSerializer(data=request.data)
        if not user_serializer.is_valid():
            logger.info('User serializer errors: %s', user_serializer.errors)
            return Response({'errors': user_serializer.errors, 'received': dict(request.data)}, status=400)

        # Safely extract fields
        role = request.data.get('rol')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        email = request.data.get('email')
        password = request.data.get('password')

        if not all([email, password, role]):
            missing = [k for k in ('email', 'password', 'rol') if not request.data.get(k)]
            return Response({'detail': f'missing required fields: {missing}'}, status=400)

        #Valida si existe el usuario o bien el email registrado
        existing_user = User.objects.filter(email=email).first()

        if existing_user:
            return Response({"message": f"Username {email} is already taken"}, 400)

        # Create user and profile
        user = User.objects.create(username=email, email=email, first_name=first_name, last_name=last_name, is_active=1)
        user.save()
        user.set_password(password)
        user.save()

        group, created = Group.objects.get_or_create(name=role)
        group.user_set.add(user)
        user.save()

        matricula = request.data.get('matricula')
        alumno = Alumnos.objects.create(user=user, matricula=matricula)
        alumno.save()

        return Response({"alumno_created_id": alumno.id }, 201)

   #Editar alumno
class AlumnosViewEdit (generics.CreateAPIView):
    permissions_classes = (permissions.IsAuthenticated)
    def put(self, request, *args, **kwargs):
        # iduser=request.data["id"]
        alumno = get_object_or_404(Alumnos, id=request.data["id"])
        alumno.matricula = request.data["matricula"]
        alumno.save()
        temp = alumno.user
        temp.first_name = request.data["first_name"]
        temp.last_name = request.data["last_name"]
        temp.save()
        user = AlumnoSerializer(alumno, many=False).data

        return Response(user,200)
    
    def delete(serlf, request, *args, **kwargs):
        alumno= get_object_or_404(Alumnos, id=request.GET.get("id"))
        try:
            alumno.user.delete()
            return Response({"details": "Alumno eliminado"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})