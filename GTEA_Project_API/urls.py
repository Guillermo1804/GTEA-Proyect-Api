
from django.urls import path

from rest_framework import generics, permissions
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
    path(
        'admins/',
        users.AdminAll.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='admins-list',
    ),
    path(
        'admins/detail/',
        users.AdminView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='admins-detail',
    ),
    path(
        'admins/edit/',
        users.AdminsViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='admins-edit',
    ),

    # Alumnos
    path(
        'alumnos/',
        alumnos.AlumnosAll.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='alumnos',
    ),
    path(
        'alumnos/detail/',
        alumnos.AlumnosView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='alumnos-detail',
    ),
    path(
        'alumnos/edit/',
        alumnos.AlumnosViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='alumnos-edit',
    ),
    path(
        'alumnos/perfil/',
        alumnos.AlumnoPerfilView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='alumnos-perfil',
    ),

    # Organizadores
    path(
        'organizadores/',
        organizador.OrganizadorAll.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='organizadores',
    ),
    path(
        'organizadores/detail/',
        organizador.OrganizadoresView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='organizadores-detail',
    ),
    path(
        'organizadores/edit/',
        organizador.OrganizadoresViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='organizadores-edit',
    ),

    # Categorías
    path(
        'categorias/',
        generics.ListCreateAPIView.as_view(
            queryset=Categorias.objects.filter(activa=True).order_by('nombre'),
            serializer_class=CategoriaSerializer,
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
            permission_classes=(permissions.IsAuthenticated,),
        ),
        name='categorias',
    ),
    path(
        'categorias/detail/',
        categorias.CategoriasView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='categorias-detail',
    ),
    path(
        'categorias/edit/',
        categorias.CategoriasViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='categorias-edit',
    ),

    # Sedes
    path(
        'sedes/',
        generics.ListCreateAPIView.as_view(
            queryset=Sedes.objects.filter(activa=True).order_by('nombre'),
            serializer_class=SedeSerializer,
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
            permission_classes=(permissions.IsAuthenticated,),
        ),
        name='sedes',
    ),
    path(
        'sedes/detail/',
        sedes.SedesView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='sedes-detail',
    ),
    path(
        'sedes/edit/',
        sedes.SedesViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='sedes-edit',
    ),

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
    path(
        'inscripciones/',
        inscripciones.InscripcionesView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='inscripciones',
    ),
    path(
        'inscripciones/mis-eventos/',
        inscripciones.InscripcionesMisEventos.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='inscripciones-mis-eventos',
    ),
    path(
        'inscripciones/detail/',
        inscripciones.InscripcionesView.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='inscripciones-detail',
    ),
    path(
        'inscripciones/edit/',
        inscripciones.InscripcionesViewEdit.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='inscripciones-edit',
    ),
 #   path('inscripciones/lista-espera/', inscripciones_lista_espera_front, name='inscripciones-lista-espera'),
   # path('inscripciones/mis-eventos/', inscripciones_mis_eventos, name='inscripciones-mis-eventos'),
    path(
        'inscripciones/cancel/',
        inscripciones.InscripcionesCancel.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='inscripciones-cancel',
    ),

    # Reportes
    path(
        'reportes/resumen/',
        reportes.ReportesResumen.as_view(
            authentication_classes=(BearerTokenAuthentication, TokenAuthentication),
        ),
        name='reportes-resumen',
    ),
]
