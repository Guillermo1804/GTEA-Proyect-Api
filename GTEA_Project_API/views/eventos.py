from django.db import transaction
from ..serializers import EventoSerializer
from ..models import Eventos
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging

logger = logging.getLogger(__name__)


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
        evento = get_object_or_404(Eventos, id=request.GET.get("id"))
        data = EventoSerializer(evento, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)

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
        evento = get_object_or_404(Eventos, id=request.data["id"])
        data = request.data

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
            evento.categoria_id = data['categoria']
        if 'sede' in data:
            evento.sede_id = data['sede'] or None
        if 'aula' in data:
            evento.aula_id = data['aula'] or None

        evento.save()
        result = EventoSerializer(evento, many=False).data
        return Response(result, 200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        evento = get_object_or_404(Eventos, id=request.GET.get("id"))
        try:
            evento.delete()
            return Response({"details": "Evento eliminado"}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error deleting evento id=%s by user_id=%s", request.GET.get("id"), getattr(request.user, 'id', None))
            return Response({"details": "Algo pasó al eliminar"}, status=status.HTTP_200_OK)
