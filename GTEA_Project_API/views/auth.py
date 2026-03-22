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

from GTEA_Project_API.authentication import clear_auth_token_cookie, set_auth_token_cookie

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})

        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        if user.is_active:
            roles = list(user.groups.values_list('name', flat=True))
            if not roles:
                return Response({"detail": "User has no role/group assigned"}, status=status.HTTP_403_FORBIDDEN)

            # Si solo es un rol especifico asignamos el elemento 0
            role_names = roles[0]

            token, created = Token.objects.get_or_create(user=user)

            if role_names == 'alumno':
                alumno = Alumnos.objects.filter(user=user).first()
                alumno = AlumnoSerializer(alumno).data
                alumno["token"] = token.key
                alumno["rol"] = "alumno"
                response = Response(alumno, 200)
                set_auth_token_cookie(response, token.key)
                return response
            if role_names == 'organizador':
                organizador = Organizadores.objects.filter(user=user).first()
                organizador = OrganizadorSerializer(organizador).data
                organizador["token"] = token.key
                organizador["rol"] = "organizador"
                response = Response(organizador, 200)
                set_auth_token_cookie(response, token.key)
                return response
            if role_names == 'administrador':
                user = UserSerializer(user, many=False).data
                user['token'] = token.key
                user["rol"] = "administrador"
                response = Response(user, 200)
                set_auth_token_cookie(response, token.key)
                return response
            else:
                return Response({"details":"Forbidden"},403)
                pass

        return Response({}, status=status.HTTP_403_FORBIDDEN)


class Logout(generics.GenericAPIView):

    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):

        print("logout")
        user = request.user
        print(str(user))
        if user.is_active:
            token = Token.objects.get(user=user)
            token.delete()

            response = Response({'logout': True})
            clear_auth_token_cookie(response)
            return response


        response = Response({'logout': False})
        clear_auth_token_cookie(response)
        return response
