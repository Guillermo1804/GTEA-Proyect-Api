from django.urls import path
from .views import alumnos
from .views import auth
from .views import categorias
from .views import eventos
from .views import inscripciones
from .views import organizador
from .views import reportes
from .views import sedes
from .views import users

urlpatterns = [
    # Auth
    path('auth/login/', auth.CustomAuthToken.as_view(), name='auth-login'),
    path('auth/logout/', auth.Logout.as_view(), name='auth-logout'),

    # Admins
    path('admins/', users.AdminAll.as_view(), name='admins-list'),
    path('admins/detail/', users.AdminView.as_view(), name='admins-detail'),
    path('admins/edit/', users.AdminsViewEdit.as_view(), name='admins-edit'),

    # Alumnos
    path('alumnos/', alumnos.AlumnosAll.as_view(), name='alumnos'),
    path('alumnos/detail/', alumnos.AlumnosView.as_view(), name='alumnos-detail'),
    path('alumnos/edit/', alumnos.AlumnosViewEdit.as_view(), name='alumnos-edit'),
    path('alumnos/perfil/', alumnos.AlumnoPerfilView.as_view(), name='alumnos-perfil'),

    # Organizadores
    path('organizadores/', organizador.OrganizadorAll.as_view(), name='organizadores'),
    path('organizadores/detail/', organizador.OrganizadoresView.as_view(), name='organizadores-detail'),
    path('organizadores/edit/', organizador.OrganizadoresViewEdit.as_view(), name='organizadores-edit'),

    # Categorías
    path('categorias/', categorias.CategoriasListCreate.as_view(), name='categorias'),
    path('categorias/detail/', categorias.CategoriasView.as_view(), name='categorias-detail'),
    path('categorias/edit/', categorias.CategoriasViewEdit.as_view(), name='categorias-edit'),

    # Sedes
    path('sedes/', sedes.SedesListCreate.as_view(), name='sedes'),
    path('sedes/detail/', sedes.SedesView.as_view(), name='sedes-detail'),
    path('sedes/edit/', sedes.SedesViewEdit.as_view(), name='sedes-edit'),

    # Aulas
    path('aulas/', sedes.AulasView.as_view(), name='aulas'),
    path('aulas/detail/', sedes.AulasView.as_view(), name='aulas-detail'),
    path('aulas/edit/', sedes.AulasViewEdit.as_view(), name='aulas-edit'),

    # Eventos
    path('eventos/', eventos.EventosView.as_view(), name='eventos'),
    path('eventos/detail/', eventos.EventosView.as_view(), name='eventos-detail'),
    path('eventos/edit/', eventos.EventosViewEdit.as_view(), name='eventos-edit'),
    path('eventos/imagen-upload/', eventos.EventoImagenUpload.as_view(), name='eventos-imagen-upload'),

    # Inscripciones (rutas específicas antes de la raíz /inscripciones/)
    path('inscripciones/mis-eventos/', inscripciones.InscripcionesMisEventos.as_view(), name='inscripciones-mis-eventos'),
    path('inscripciones/cancel/', inscripciones.InscripcionesCancel.as_view(), name='inscripciones-cancel'),
    path('inscripciones/lista-espera/', inscripciones.InscripcionesListaEspera.as_view(), name='inscripciones-lista-espera'),
    path('inscripciones/detail/', inscripciones.InscripcionesView.as_view(), name='inscripciones-detail'),
    path('inscripciones/edit/', inscripciones.InscripcionesViewEdit.as_view(), name='inscripciones-edit'),
    path('inscripciones/', inscripciones.InscripcionesView.as_view(), name='inscripciones'),

    # Reportes
    path('reportes/resumen/', reportes.ReportesResumen.as_view(), name='reportes-resumen'),
]

# Archivos subidos (imágenes de eventos, etc.)
# `static(MEDIA_URL, ...)` solo añade rutas cuando DEBUG=True; con DEBUG=False (default en
# settings) las peticiones a /media/... daban 404. Servimos MEDIA siempre desde Django;
# en producción conviene que nginx sirva /media/ antes de llegar aquí (más eficiente).
from django.conf import settings
from django.urls import re_path
from django.views.static import serve

if getattr(settings, 'MEDIA_URL', None) and getattr(settings, 'MEDIA_ROOT', None):
    _media_prefix = settings.MEDIA_URL.lstrip('/')
    if _media_prefix and not _media_prefix.endswith('/'):
        _media_prefix += '/'
    urlpatterns += [
        re_path(
            rf'^{_media_prefix}(?P<path>.*)$',
            serve,
            {'document_root': settings.MEDIA_ROOT},
        ),
    ]
