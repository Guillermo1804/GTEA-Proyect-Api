from django.db import transaction
from django.db.models import Count, Q
from ..authentication import DEFAULT_API_AUTH
from ..serializers import EventoSerializer
from ..models import Eventos
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.core.files.storage import FileSystemStorage
import logging
import re
import os
import uuid

logger = logging.getLogger(__name__)

def _user_in_group(user, group_name: str) -> bool:
    """
    El proyecto identifica roles por `user.groups` con nombres:
    - `alumno`
    - `organizador`
    - `administrador`
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return user.groups.filter(name=group_name).exists()


def _is_admin(user) -> bool:
    return _user_in_group(user, "administrador")


def _is_organizador(user) -> bool:
    return _user_in_group(user, "organizador")


def _eventos_queryset_for_user(request, base_qs):
    """
    Regla de permisos solicitada:
    - Admin: ve todos.
    - Organizador: solo sus propios eventos.
    - Alumno (u otros roles): por compatibilidad mantenemos comportamiento actual (ver todos en listados).
    """
    if _is_admin(request.user):
        return base_qs
    if _is_organizador(request.user):
        return base_qs.filter(organizador=request.user)
    return base_qs


def _assert_can_modify_evento(request, evento: Eventos) -> None:
    """
    Regla de permisos solicitada:
    - Admin: puede modificar cualquier evento.
    - Organizador: solo si el evento pertenece a su usuario.
    - Otros: no pueden modificar.
    """
    if _is_admin(request.user):
        return
    if not _is_organizador(request.user):
        raise PermissionError("Forbidden")
    if evento.organizador_id != request.user.id:
        # Ocultamos el recurso ajeno al organizador (evita enumeración).
        raise PermissionError("Forbidden")


def _normalize_evento_payload(data: dict) -> dict:
    def _coerce_fk_id(value):
        if value is None:
            return None
        if isinstance(value, dict):
            if 'id' in value:
                value = value.get('id')
            else:
                return None
        if isinstance(value, str):
            stripped = value.strip()
            if stripped == '' or stripped.lower() in ('null', 'none', 'undefined'):
                return None
            if stripped.isdigit():
                return int(stripped)
            match = re.search(r'(\d+)', stripped)
            if match:
                return int(match.group(1))
            return value
        return value

    mapping = {
        'categoriaId': 'categoria',
        'sedeId': 'sede',
        'aulaId': 'aula',
        'imagenPortada': 'imagen_portada',
        'fechaInicio': 'fecha_inicio',
        'horaInicio': 'hora_inicio',
        'fechaFin': 'fecha_fin',
        'horaFin': 'hora_fin',
        'cupoMaximo': 'cupo_maximo',
        'costoEntrada': 'costo_entrada',
        'listaEspera': 'lista_espera',
        'publicarInmediatamente': 'publicar_inmediatamente',
        'esOrganizador': 'es_organizador',
    }

    for camel_key, snake_key in mapping.items():
        if camel_key not in data:
            continue

        # Si viene el camelCase, siempre preferirlo (evita que `categoria: null` gane sobre `categoriaId: 2`)
        camel_value = data.get(camel_key)
        if camel_value is not None and camel_value != '':
            data[snake_key] = camel_value
        elif snake_key not in data:
            data[snake_key] = camel_value

    # Coerción de llaves foráneas a IDs consistentes
    for fk in ('categoria', 'sede', 'aula'):
        if fk in data:
            data[fk] = _coerce_fk_id(data.get(fk))
    return data


def _eventos_qs_with_inscritos():
    """Alineado con Eventos.inscritos (solo tipo 'inscrito')."""
    return Eventos.objects.annotate(
        num_inscritos=Count('inscripciones', filter=Q(inscripciones__tipo='inscrito')),
    )


class EventosAll(generics.CreateAPIView):
    """GET /lista-eventos/  → lista de eventos"""
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        base = _eventos_qs_with_inscritos().order_by("-fecha_inicio")
        eventos = _eventos_queryset_for_user(request, base)
        lista = EventoSerializer(eventos, many=True).data
        return Response(lista, 200)


class EventosPublicList(generics.GenericAPIView):
    """
    GET /eventos/public/ — catálogo público (sin autenticación).
    Solo eventos en estado Activo.
    """
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def get(self, request, *args, **kwargs):
        qs = (
            _eventos_qs_with_inscritos()
            .filter(status='Activo')
            .order_by('-fecha_inicio')
        )
        return Response(EventoSerializer(qs, many=True).data, status=status.HTTP_200_OK)


class EventosView(generics.CreateAPIView):
    """GET /evento/?id={id}  → obtener evento por ID
       POST /evento/         → crear evento
    """
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        evento_id = request.GET.get("id")
        base_qs = _eventos_qs_with_inscritos()
        if evento_id:
            if _is_admin(request.user):
                evento = get_object_or_404(base_qs, id=evento_id)
            elif _is_organizador(request.user):
                evento = get_object_or_404(
                    _eventos_queryset_for_user(request, base_qs),
                    id=evento_id,
                )
            else:
                evento = get_object_or_404(base_qs, id=evento_id)
            data = EventoSerializer(evento, many=False).data
            return Response(data, 200)

        eventos = _eventos_queryset_for_user(
            request,
            base_qs.order_by("-fecha_inicio"),
        )
        lista = EventoSerializer(eventos, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        if not (_is_admin(request.user) or _is_organizador(request.user)):
            return Response({"details": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        data = _normalize_evento_payload(data)

        # Determinar status según publicar_inmediatamente (snake_case)
        if data.get('publicar_inmediatamente') in [True, 'true', '1', 1, 'True']:
            data['status'] = 'Activo'
        else:
            data['status'] = data.get('status') or 'Borrador'

        # Asignar organizador al usuario autenticado
        data['organizador'] = request.user.id

        # Limpiar campos vacíos opcionales para FK
        for fk in ('sede', 'aula', 'categoria'):
            if fk in data and (data[fk] == '' or data[fk] is None):
                data[fk] = None

        serializer = EventoSerializer(data=data)
        if serializer.is_valid():
            evento = serializer.save()
            return Response({"evento_created_id": evento.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EventosViewEdit(generics.CreateAPIView):
    """PUT    /eventos-edit/      → editar evento
       DELETE /eventos-edit/?id={id}  → eliminar evento
    """
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        evento_id = request.data.get("id") or request.data.get("evento_id") or request.data.get("eventoId")
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        data = _normalize_evento_payload(data)

        if not evento_id:
            return Response({"details": "Falta el campo id"}, status=status.HTTP_400_BAD_REQUEST)
        evento = get_object_or_404(Eventos, id=evento_id)
        try:
            _assert_can_modify_evento(request, evento)
        except PermissionError:
            return Response({"details": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        direct_fields = [
            'titulo', 'descripcion', 'modalidad', 'status',
            'imagen_portada', 'fecha_inicio', 'hora_inicio',
            'fecha_fin', 'hora_fin', 'cupo_maximo', 'costo_entrada',
            'lista_espera', 'publicar_inmediatamente', 'es_organizador'
        ]
        for field in direct_fields:
            if field in data:
                setattr(evento, field, data[field])

        if 'categoria' in data:
            evento.categoria_id = data['categoria'] or None
        if 'sede' in data:
            evento.sede_id = data['sede'] or None
        if 'aula' in data:
            evento.aula_id = data['aula'] or None

        evento.save()
        result = EventoSerializer(evento, many=False).data
        return Response(result, 200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        evento_id = request.GET.get("id")
        if not evento_id:
            return Response({"details": "Falta el parámetro id"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            evento = get_object_or_404(Eventos, id=evento_id)
            try:
                _assert_can_modify_evento(request, evento)
            except PermissionError:
                return Response({"details": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

            evento.delete()
            return Response({"details": "Evento eliminado", "deleted_id": int(evento_id)}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception(
                "Error deleting evento id=%s by user_id=%s",
                evento_id,
                getattr(request.user, 'id', None),
            )
            return Response({"details": "Error al eliminar"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EventoImagenUpload(generics.CreateAPIView):
    """
    POST /eventos/imagen-upload/
      - Recibe un archivo multipart con el campo `imagen`
      - Guarda el archivo en `MEDIA_ROOT/eventos/` y devuelve una URL absoluta

    Nota: el modelo `Eventos.imagen_portada` es un URLField, así que devolvemos
    una URL válida (ej: https://tu-dominio/media/eventos/<archivo>.jpg).
    """

    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        uploaded = request.FILES.get("imagen") or request.FILES.get("file")
        if not uploaded:
            return Response({"details": "Falta el archivo 'imagen' (multipart/form-data)"}, status=status.HTTP_400_BAD_REQUEST)

        valid_types = ("image/png", "image/jpeg")
        if getattr(uploaded, "content_type", None) not in valid_types:
            return Response(
                {"details": "Tipo de archivo no permitido. Solo PNG/JPG"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        max_size = 5 * 1024 * 1024  # 5MB
        if uploaded.size > max_size:
            return Response({"details": "La imagen no debe superar 5MB"}, status=status.HTTP_400_BAD_REQUEST)

        _, ext = os.path.splitext(uploaded.name)
        ext = ext.lower()
        if ext not in (".png", ".jpg", ".jpeg"):
            # Fallback: si el nombre viene raro, inferimos por content_type
            ext = ".png" if uploaded.content_type == "image/png" else ".jpg"

        eventos_dir = os.path.join(settings.MEDIA_ROOT, "eventos")
        base_url = f"{settings.MEDIA_URL.rstrip('/')}/eventos"

        storage = FileSystemStorage(location=eventos_dir, base_url=base_url)

        filename = f"{uuid.uuid4().hex}{ext}"
        saved_name = storage.save(filename, uploaded)
        url = storage.url(saved_name)  # '/media/eventos/<file>'
        absolute_url = request.build_absolute_uri(url)

        return Response({"imagen_url": absolute_url}, status=status.HTTP_201_CREATED)
