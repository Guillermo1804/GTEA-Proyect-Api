from django.db import transaction
from ..serializers import EventoSerializer
from ..models import Eventos
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging

logger = logging.getLogger(__name__)


def _normalize_evento_payload(data: dict) -> dict:
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
        if snake_key not in data and camel_key in data:
            data[snake_key] = data[camel_key]
    return data


class EventosAll(generics.CreateAPIView):
    """GET /lista-eventos/  → lista de eventos"""
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        eventos = Eventos.objects.all().order_by("-fecha_inicio")
        lista = EventoSerializer(eventos, many=True).data
        return Response(lista, 200)


class EventosView(generics.CreateAPIView):
    """GET /evento/?id={id}  → obtener evento por ID
       POST /evento/         → crear evento
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        evento_id = request.GET.get("id")
        if evento_id:
            evento = get_object_or_404(Eventos, id=evento_id)
            data = EventoSerializer(evento, many=False).data
            return Response(data, 200)

        eventos = Eventos.objects.all().order_by("-fecha_inicio")
        lista = EventoSerializer(eventos, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
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
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        data = _normalize_evento_payload(data)

        evento_id = data.get("id") or request.data.get("id")
        if not evento_id:
            return Response({"details": "Falta el campo id"}, status=status.HTTP_400_BAD_REQUEST)
        evento = get_object_or_404(Eventos, id=evento_id)

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
            deleted_count, _ = Eventos.objects.filter(id=evento_id).delete()
            if deleted_count == 0:
                return Response({"details": "Evento no encontrado"}, status=status.HTTP_404_NOT_FOUND)
            return Response({"details": "Evento eliminado", "deleted_id": int(evento_id)}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception(
                "Error deleting evento id=%s by user_id=%s",
                evento_id,
                getattr(request.user, 'id', None),
            )
            return Response({"details": "Error al eliminar"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
