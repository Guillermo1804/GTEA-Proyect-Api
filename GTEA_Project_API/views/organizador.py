from django.shortcuts import render
from django.db.models import *
from django.db import transaction
from GTEA_Project_API.authentication import DEFAULT_API_AUTH
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

class OrganizadorAll(generics.CreateAPIView):
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        organizador = Organizadores.objects.all().order_by("id")
        organizador = OrganizadorSerializer(organizador, many=True).data

        return Response(organizador, 200)

class OrganizadoresView(generics.CreateAPIView):
    #Obtener usuario por ID
    # permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = DEFAULT_API_AUTH

    def get(self, request, *args, **kwargs):
        organizador = get_object_or_404(Organizadores, id = request.GET.get("id"))
        organizador = OrganizadorSerializer(organizador, many=False).data
        return Response(organizador, 200)
    
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

            organizador = Organizadores.objects.create(user=user,
                                                       id_trabajador= request.data.get("id_trabajador"))
            organizador.save()

            return Response({"organizador_created_id": organizador.id }, 201)

        return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)

#Se tiene que modificar la parte de edicion y eliminar
class OrganizadoresViewEdit(generics.CreateAPIView):
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    def put(self, request, *args, **kwargs):
        org_id = request.data.get("id")
        if org_id is None:
            return Response({"details": "Falta el campo id"}, status=status.HTTP_400_BAD_REQUEST)
        organizador = get_object_or_404(Organizadores, id=org_id)
        organizador.id_trabajador = request.data.get("id_trabajador", organizador.id_trabajador)
        organizador.save()
        temp = organizador.user
        if "first_name" in request.data:
            temp.first_name = request.data.get("first_name", temp.first_name)
        if "last_name" in request.data:
            temp.last_name = request.data.get("last_name", temp.last_name)
        if password := request.data.get("password"):
            pw = str(password).strip()
            if pw:
                temp.set_password(pw)
        temp.save()
        user = OrganizadorSerializer(organizador, many=False).data

        return Response(user,200)
    
    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        organizador= get_object_or_404(Organizadores, id=request.GET.get("id"))
        try:
            organizador.user.delete()
            return Response({"details": "Organizador eliminado"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})


class OrganizadorIsActivePatch(APIView):
    """PATCH /organizador/<pk>/ — solo administradores; body: { is_active: bool }"""
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def patch(self, request, pk, *args, **kwargs):
        from GTEA_Project_API.views.users import _request_user_is_admin

        if not _request_user_is_admin(request.user):
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if "is_active" not in request.data:
            return Response({"detail": "is_active es requerido"}, status=status.HTTP_400_BAD_REQUEST)
        organizador = get_object_or_404(Organizadores, pk=pk)
        val = request.data.get("is_active")
        if isinstance(val, str):
            organizador.user.is_active = val.strip().lower() in ("1", "true", "yes", "on")
        else:
            organizador.user.is_active = bool(val)
        organizador.user.save(update_fields=["is_active"])
        return Response(OrganizadorSerializer(organizador).data, status=status.HTTP_200_OK)
