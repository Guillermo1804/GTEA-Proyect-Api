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
from django.contrib import admin
from django.urls import path
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

    # Django admin
    path('admin/', admin.site.urls),

    # Authentication
    path('auth/login/', auth.CustomAuthToken.as_view(), name='auth-login'),
    path('auth/logout/', auth.Logout.as_view(), name='auth-logout'),

    # Administradores / Usuarios
    path('admins/', users.AdminAll.as_view(), name='admins-list'),
    path('admins/detail/', users.AdminView.as_view(), name='admins-detail'),
    path('admins/edit/', users.AdminsViewEdit.as_view(), name='admins-edit'),
    path('users/register/', users.register_user, name='users-register'),

    # Organizadores
    path('organizadores/', organizador.OrganizadorAll.as_view(), name='organizadores-list'),
    path('organizadores/detail/', organizador.OrganizadoresView.as_view(), name='organizadores-detail'),
    path('organizadores/edit/', organizador.OrganizadoresViewEdit.as_view(), name='organizadores-edit'),

    # Alumnos
    path('alumnos/', alumnos.AlumnosAll.as_view(), name='alumnos-list'),
    path('alumnos/detail/', alumnos.AlumnosView.as_view(), name='alumnos-detail'),
    path('alumnos/edit/', alumnos.AlumnosViewEdit.as_view(), name='alumnos-edit'),

    # Categorías
    path('categorias/', categorias.CategoriasAll.as_view(), name='categorias-list'),
    path('categorias/detail/', categorias.CategoriasDetail.as_view(), name='categorias-detail'),
    path('categorias/edit/', categorias.CategoriasEdit.as_view(), name='categorias-edit'),

    # Sedes
    path('sedes/', sedes.SedesAll.as_view(), name='sedes-list'),
    path('sedes/detail/', sedes.SedesDetail.as_view(), name='sedes-detail'),
    path('sedes/edit/', sedes.SedesEdit.as_view(), name='sedes-edit'),

    # Aulas
    path('aulas/', sedes.AulasAll.as_view(), name='aulas-list'),
    path('aulas/edit/', sedes.AulasEdit.as_view(), name='aulas-edit'),

    # Eventos
    path('eventos/', eventos.EventosAll.as_view(), name='eventos-list'),
    path('eventos/detail/', eventos.EventosDetail.as_view(), name='eventos-detail'),
    path('eventos/edit/', eventos.EventosEdit.as_view(), name='eventos-edit'),

    # Inscripciones
    path('inscripciones/', inscripciones.InscripcionesAll.as_view(), name='inscripciones-list'),
    path('inscripciones/lista-espera/', inscripciones.InscripcionesListaEspera.as_view(), name='inscripciones-lista-espera'),
    path('inscripciones/cancel/', inscripciones.InscripcionesCancel.as_view(), name='inscripciones-cancel'),

    # Reportes
    path('reportes/resumen/', reportes.ReportesResumen.as_view(), name='reportes-resumen'),
]
