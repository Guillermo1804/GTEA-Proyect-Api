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
    path('django-admin/', admin.site.urls),

    # Auth (sistema-fcc-api style)
    path('token/', auth.CustomAuthToken.as_view(), name='auth-token'),
    path('logout/', auth.Logout.as_view(), name='auth-logout'),

    # Administradores
    path('admin/', users.AdminView.as_view(), name='admin-create-detail'),
    path('lista-admins/', users.AdminAll.as_view(), name='admins-list'),
    path('admins-edit/', users.AdminsViewEdit.as_view(), name='admins-edit'),

    # Organizadores
    path('organizadores/', organizador.OrganizadoresView.as_view(), name='organizadores-create-detail'),
    path('lista-organizadores/', organizador.OrganizadorAll.as_view(), name='organizadores-list'),
    path('organizadores-edit/', organizador.OrganizadoresViewEdit.as_view(), name='organizadores-edit'),

    # Alumnos
    path('alumnos/', alumnos.AlumnosView.as_view(), name='alumnos-create-detail'),
    path('lista-alumnos/', alumnos.AlumnosAll.as_view(), name='alumnos-list'),
    path('alumnos-edit/', alumnos.AlumnosViewEdit.as_view(), name='alumnos-edit'),

    # Categorías
    path('categoria/', categorias.CategoriasView.as_view(), name='categorias-create-detail'),
    path('lista-categorias/', categorias.CategoriasAll.as_view(), name='categorias-list'),
    path('categorias-edit/', categorias.CategoriasViewEdit.as_view(), name='categorias-edit'),

    # Sedes
    path('sede/', sedes.SedesView.as_view(), name='sedes-create-detail'),
    path('lista-sedes/', sedes.SedesAll.as_view(), name='sedes-list'),
    path('sedes-edit/', sedes.SedesViewEdit.as_view(), name='sedes-edit'),

    # Aulas
    path('aula/', sedes.AulasView.as_view(), name='aulas-create-detail'),
    path('lista-aulas/', sedes.AulasAll.as_view(), name='aulas-list'),
    path('aulas-edit/', sedes.AulasViewEdit.as_view(), name='aulas-edit'),

    # Eventos
    path('evento/', eventos.EventosView.as_view(), name='eventos-create-detail'),
    path('lista-eventos/', eventos.EventosAll.as_view(), name='eventos-list'),
    path('eventos-edit/', eventos.EventosViewEdit.as_view(), name='eventos-edit'),

    # Inscripciones
    path('inscripcion/', inscripciones.InscripcionesView.as_view(), name='inscripciones-create-detail'),
    path('lista-inscripciones/', inscripciones.InscripcionesAll.as_view(), name='inscripciones-list'),
    path('inscripciones-edit/', inscripciones.InscripcionesViewEdit.as_view(), name='inscripciones-edit'),
    path('inscripciones-lista-espera/', inscripciones.InscripcionesListaEspera.as_view(), name='inscripciones-lista-espera'),
    path('inscripciones-cancel/', inscripciones.InscripcionesCancel.as_view(), name='inscripciones-cancel'),

    # Reportes
    path('reportes-resumen/', reportes.ReportesResumen.as_view(), name='reportes-resumen'),
]
