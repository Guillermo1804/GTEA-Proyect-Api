from django.db import transaction
from ..serializers import EventoSerializer
from ..models import Eventos
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging
from ..permissions import IsAdminOrAuthenticated

logger = logging.getLogger(__name__)


class EventosAll(generics.CreateAPIView):
    """GET  /eventos/  → lista de eventos
       POST /eventos/  → crear nuevo evento
    """
    permission_classes = (IsAdminOrAuthenticated,)

    def get(self, request, *args, **kwargs):
        eventos = Eventos.objects.all().order_by("-fecha_inicio")
        lista = EventoSerializer(eventos, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        # Mapear campos camelCase del frontend a snake_case del modelo
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)

        # Mapping camelCase → snake_case
        field_map = {
            'categoriaId': 'categoria',
            'imagenPortada': 'imagen_portada',
            'fechaInicio': 'fecha_inicio',
            'horaInicio': 'hora_inicio',
            'fechaFin': 'fecha_fin',
            'horaFin': 'hora_fin',
            'sedeId': 'sede',
            'aulaId': 'aula',
            'cupoMaximo': 'cupo_maximo',
            'costoEntrada': 'costo_entrada',
            'listaEspera': 'lista_espera',
            'publicarInmediatamente': 'publicar_inmediatamente',
            'esOrganizador': 'es_organizador',
        }
        for camel, snake in field_map.items():
            if camel in data and snake not in data:
                data[snake] = data.pop(camel)

        # Determinar status según publicar_inmediatamente
        if data.get('publicar_inmediatamente') in [True, 'true', '1']:
            data['status'] = 'Activo'
        else:
            data['status'] = 'Borrador'

        # Asignar organizador al usuario autenticado
        data['organizador'] = request.user.id

        # Limpiar campos vacíos opcionales para FK
        for fk in ('sede', 'aula', 'categoria'):
            if fk in data and (data[fk] == '' or data[fk] is None):
                data[fk] = None

        # Sanitizar imagen_portada: convertir null / valores no-string a cadena vacía
        img = data.get('imagen_portada')
        if img is None or not isinstance(img, str):
            data['imagen_portada'] = ''

        serializer = EventoSerializer(data=data)
        if serializer.is_valid():
            evento = serializer.save()
            return Response({"evento_created_id": evento.id, "success": True}, status=status.HTTP_201_CREATED)
        logger.error("EventoSerializer errors: %s | data received: %s", serializer.errors, data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EventosDetail(generics.CreateAPIView):
    """GET /eventos/detail/?id={id}  → obtener evento por ID"""
    permission_classes = (IsAdminOrAuthenticated,)

    def get(self, request, *args, **kwargs):
        evento = get_object_or_404(Eventos, id=request.GET.get("id"))
        data = EventoSerializer(evento, many=False).data
        return Response(data, 200)


class EventosEdit(generics.CreateAPIView):
    """PUT    /eventos/edit/?id={id}  → editar evento
       DELETE /eventos/edit/?id={id}  → eliminar (cancelar) evento
    """
    permission_classes = (IsAdminOrAuthenticated,)

    def put(self, request, *args, **kwargs):
        evento_id = request.data.get("id") or request.GET.get("id")
        evento = get_object_or_404(Eventos, id=evento_id)

        # Mapear campos camelCase
        field_map = {
            'categoriaId': 'categoria_id',
            'imagenPortada': 'imagen_portada',
            'fechaInicio': 'fecha_inicio',
            'horaInicio': 'hora_inicio',
            'fechaFin': 'fecha_fin',
            'horaFin': 'hora_fin',
            'sedeId': 'sede_id',
            'aulaId': 'aula_id',
            'cupoMaximo': 'cupo_maximo',
            'costoEntrada': 'costo_entrada',
            'listaEspera': 'lista_espera',
            'publicarInmediatamente': 'publicar_inmediatamente',
            'esOrganizador': 'es_organizador',
        }

        data = request.data
        for camel, snake in field_map.items():
            if camel in data:
                setattr(evento, snake, data[camel])

        # Campos directos (snake_case)
        direct_fields = ['titulo', 'descripcion', 'modalidad', 'status',
                         'imagen_portada', 'fecha_inicio', 'hora_inicio',
                         'fecha_fin', 'hora_fin', 'cupo_maximo', 'costo_entrada',
                         'lista_espera', 'publicar_inmediatamente', 'es_organizador']
        for field in direct_fields:
            if field in data:
                setattr(evento, field, data[field])

        # FK directos
        if 'categoria' in data:
            evento.categoria_id = data['categoria']
        if 'sede' in data:
            evento.sede_id = data['sede'] or None
        if 'aula' in data:
            evento.aula_id = data['aula'] or None

        evento.save()
        result = EventoSerializer(evento, many=False).data
        return Response(result, 200)

    def delete(self, request, *args, **kwargs):
        evento = get_object_or_404(Eventos, id=request.GET.get("id"))
        try:
            evento.status = 'Cancelado'
            evento.save()
            return Response({"details": "Evento cancelado"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})
