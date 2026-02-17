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
]
