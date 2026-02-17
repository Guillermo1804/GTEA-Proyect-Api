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
    #Create Admin
        path('admin/', users.AdminView.as_view()),
    #Admin Data
        path('lista-admins/', users.AdminAll.as_view()),
    #Edit Admin
        path('admins-edit/', users.AdminsViewEdit.as_view()),
    #Create Alumno
        path('alumnos/', alumnos.AlumnosView.as_view()),
    #Alumno Data
        path('lista-alumnos/', alumnos.AlumnosAll.as_view()),
    #Edit Alumno
        path('alumnos-edit/', alumnos.AlumnosViewEdit.as_view()),
    #Create Maestro
        path('organizadores/', organizador.OrganizadoresView.as_view()),
    #Maestro Data
        path('lista-organizadores/', organizador.OrganizadorAll.as_view()),
    #Edit Maestro
        path('organizadores-edit/', organizador.OrganizadoresViewEdit.as_view()),
    #Login
        path('token/', auth.CustomAuthToken.as_view()),
    #Logout
        path('logout/', auth.Logout.as_view()),

]
