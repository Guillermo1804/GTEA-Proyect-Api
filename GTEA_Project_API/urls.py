"""
URL configuration for GTEA_Project_API project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path

from rest_framework import generics
from rest_framework.authentication import TokenAuthentication

from .models import BearerTokenAuthentication, Categorias, Sedes
from .serializers import CategoriaSerializer, SedeSerializer
from .views import alumnos
from .views import auth
from .views import organizador
from .views import users
from .views import categorias
from .views import sedes
from .views import eventos
from .views import inscripciones
from .views import reportes

urlpatterns = [
    # ═════════════════════════════════════════════════════════
    # Frontend-compatible endpoints (NO tocar el front)
    # ═════════════════════════════════════════════════════════

    # Auth
    path('auth/login/', auth.CustomAuthToken.as_view(), name='auth-login'),
    path('auth/logout/', auth.Logout.as_view(), name='auth-logout'),

    # Admins
    path('admins/', users.AdminAll.as_view(), name='admins-list'),
    path('admins/detail/', users.AdminView.as_view(), name='admins-detail'),
    path('admins/edit/', users.AdminsViewEdit.as_view(), name='admins-edit'),

    # Alumnos
    path('alumnos/detail/', alumnos.AlumnosView.as_view(), name='alumnos-detail'),
    path('alumnos/edit/', alumnos.AlumnosViewEdit.as_view(), name='alumnos-edit'),
#       path('alumnos/perfil/', alumnos_perfil, name='alumnos-perfil-front'),

    # Organizadores
    path('organizadores/detail/', organizador.OrganizadoresView.as_view(), name='organizadores-detail'),
    path('organizadores/edit/', organizador.OrganizadoresViewEdit.as_view(), name='organizadores-edit'),

    # Categorías
    path(
        'categorias/',
        generics.ListCreateAPIView.as_view(
            queryset=Categorias.objects.filter(activa=True).order_by('nombre'),
            serializer_class=CategoriaSerializer,
        ),
        name='categorias',
    ),
    path('categorias/detail/', categorias.CategoriasView.as_view(), name='categorias-detail'),
    path('categorias/edit/', categorias.CategoriasViewEdit.as_view(), name='categorias-edit'),

    # Sedes
    path(
        'sedes/',
        generics.ListCreateAPIView.as_view(
            queryset=Sedes.objects.filter(activa=True).order_by('nombre'),
            serializer_class=SedeSerializer,
        ),
        name='sedes',
    ),
    path('sedes/detail/', sedes.SedesView.as_view(), name='sedes-detail'),
    path('sedes/edit/', sedes.SedesViewEdit.as_view(), name='sedes-edit'),

    # Aulas
    path(
        'aulas/',
        sedes.AulasView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='aulas',
    ),
    path(
        'aulas/detail/',
        sedes.AulasView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='aulas-detail',
    ),
    path(
        'aulas/edit/',
        sedes.AulasViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='aulas-edit',
    ),

    # Eventos
    path(
        'eventos/',
        eventos.EventosView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='eventos',
    ),
    path(
        'eventos/detail/',
        eventos.EventosView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='eventos-detail',
    ),
    path(
        'eventos/edit/',
        eventos.EventosViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='eventos-edit',
    ),

    # Inscripciones
    path('inscripciones/detail/', inscripciones.InscripcionesView.as_view(), name='inscripciones-detail'),
    path('inscripciones/edit/', inscripciones.InscripcionesViewEdit.as_view(), name='inscripciones-edit'),
 #   path('inscripciones/lista-espera/', inscripciones_lista_espera_front, name='inscripciones-lista-espera'),
   # path('inscripciones/mis-eventos/', inscripciones_mis_eventos, name='inscripciones-mis-eventos'),
    #path('inscripciones/cancel/', inscripciones_cancel_front, name='inscripciones-cancel'),

    # Reportes
    path('reportes/resumen/', reportes.ReportesResumen.as_view(), name='reportes-resumen'),
]
