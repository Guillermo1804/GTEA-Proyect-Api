from django.db import transaction
from ..serializers import InscripcionSerializer
from ..models import Inscripciones, Eventos, Alumnos
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


def _estado_evento_para_alumno(evento, inscripcion) -> str:
    """Mapea estado del backend a los tabs del frontend del alumno."""
    if getattr(inscripcion, 'tipo', None) == 'lista_espera':
        return 'lista-espera'

    status = getattr(evento, 'status', None)
    if status == 'Cancelado':
        return 'cancelado'
    if status == 'Finalizado':
        return 'completado'

    hoy = timezone.localdate()
    fecha_fin = getattr(evento, 'fecha_fin', None)
    if fecha_fin and fecha_fin < hoy:
        return 'completado'
    return 'proximo'


class InscripcionesMisEventos(generics.CreateAPIView):
    """GET /inscripciones/mis-eventos/ → eventos del alumno autenticado."""
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        try:
            alumno = Alumnos.objects.get(user=request.user)
        except Alumnos.DoesNotExist:
            return Response({"details": "Forbidden", "mensaje": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        qs = (
            Inscripciones.objects
            .filter(alumno=alumno)
            .select_related('evento', 'evento__categoria', 'evento__sede', 'evento__aula')
            .order_by('-creation')
        )

        # Precalcular posición de lista de espera por evento
        waitlist_positions = {}
        waitlist = (
            Inscripciones.objects
            .filter(alumno=alumno, tipo='lista_espera')
            .select_related('evento')
            .order_by('evento_id', 'creation')
        )
        current_event_id = None
        position = 0
        for insc in waitlist:
            if insc.evento_id != current_event_id:
                current_event_id = insc.evento_id
                position = 1
            else:
                position += 1
            waitlist_positions[insc.id] = position

        data = []
        for inscripcion in qs:
            evento = inscripcion.evento
            item = {
                'evento_id': evento.id,
                'evento_titulo': evento.titulo,
                'categoria_nombre': getattr(evento.categoria, 'nombre', '') if evento.categoria_id else '',
                'fecha_inicio': evento.fecha_inicio,
                'hora_inicio': evento.hora_inicio,
                'modalidad': evento.modalidad,
                'sede_nombre': getattr(evento.sede, 'nombre', '') if evento.sede_id else '',
                'aula_nombre': getattr(evento.aula, 'nombre', '') if evento.aula_id else '',
                'imagen_portada': evento.imagen_portada,
                'estado': _estado_evento_para_alumno(evento, inscripcion),
                'posicion_lista_espera': waitlist_positions.get(inscripcion.id),
                'tiene_certificado': False,
            }
            data.append(item)

        return Response(data, status=status.HTTP_200_OK)


class InscripcionesAll(generics.CreateAPIView):
    """GET /lista-inscripciones/  → listar inscripciones (filtrable por evento_id o alumno_id)."""
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        """Listar inscripciones (filtrable por evento_id o alumno_id)."""
        qs = Inscripciones.objects.all().order_by("-creation")
        evento_id = request.GET.get("evento_id")
        alumno_id = request.GET.get("alumno_id")
        if evento_id:
            qs = qs.filter(evento_id=evento_id)
        if alumno_id:
            qs = qs.filter(alumno_id=alumno_id)
        lista = InscripcionSerializer(qs, many=True).data
        return Response(lista, 200)


class InscripcionesView(generics.CreateAPIView):
    """GET /inscripcion/?id={id}  → obtener inscripción por ID
       POST /inscripcion/         → inscribirse a un evento
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        inscripcion = get_object_or_404(Inscripciones, id=request.GET.get("id"))
        data = InscripcionSerializer(inscripcion, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        evento_id = request.data.get("evento_id") or request.data.get("eventoId")
        if not evento_id:
            return Response({"details": "evento_id es requerido", "mensaje": "evento_id es requerido"}, status=400)

        try:
            alumno = Alumnos.objects.get(user=request.user)
        except Alumnos.DoesNotExist:
            return Response({"details": "Forbidden", "mensaje": "Forbidden"}, status=403)

        evento = get_object_or_404(Eventos, id=evento_id)

        if Inscripciones.objects.filter(evento=evento, alumno=alumno).exists():
            return Response({"details": "El alumno ya está inscrito", "mensaje": "El alumno ya está inscrito"}, status=400)

        inscritos = evento.inscripciones.filter(tipo='inscrito').count()
        if inscritos >= evento.cupo_maximo:
            if evento.lista_espera:
                inscripcion = Inscripciones.objects.create(evento=evento, alumno=alumno, tipo='lista_espera')
                inscripcion.save()
                return Response(
                    {
                        "inscripcion_created_id": inscripcion.id,
                        "details": "Lista de espera",
                        "mensaje": "Lista de espera",
                        "tipo": "lista_espera",
                    },
                    status=status.HTTP_201_CREATED,
                )
            return Response(
                {"details": "Evento lleno", "mensaje": "Evento lleno"},
                status=status.HTTP_409_CONFLICT,
            )

        inscripcion = Inscripciones.objects.create(evento=evento, alumno=alumno, tipo='inscrito')
        inscripcion.save()
        return Response(
            {
                "inscripcion_created_id": inscripcion.id,
                "details": "Inscripción exitosa",
                "mensaje": "Inscripción exitosa",
                "tipo": "inscrito",
            },
            status=status.HTTP_201_CREATED,
        )


class InscripcionesViewEdit(generics.CreateAPIView):
    """PUT    /inscripciones-edit/      → editar inscripción
       DELETE /inscripciones-edit/?id={id}  → eliminar inscripción
    """
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        inscripcion = get_object_or_404(Inscripciones, id=request.data["id"])
        if "tipo" in request.data:
            inscripcion.tipo = request.data["tipo"]
        inscripcion.save()
        data = InscripcionSerializer(inscripcion, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        inscripcion = get_object_or_404(Inscripciones, id=request.GET.get("id"))
        try:
            inscripcion.delete()
            return Response({"details": "Inscripción eliminada"}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error deleting inscripcion id=%s by user_id=%s", request.GET.get("id"), getattr(request.user, 'id', None))
            return Response({"details": "Algo pasó al eliminar"}, status=status.HTTP_200_OK)


class InscripcionesListaEspera(generics.CreateAPIView):
    """POST /inscripciones/lista-espera/  → inscribirse a la lista de espera"""
    permission_classes = (permissions.IsAuthenticated,)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        evento_id = request.data.get("evento_id")
        alumno_id = request.data.get("alumno_id")

        if not evento_id or not alumno_id:
            return Response({"detail": "evento_id y alumno_id son requeridos"}, status=400)

        evento = get_object_or_404(Eventos, id=evento_id)
        alumno = get_object_or_404(Alumnos, id=alumno_id)

        if Inscripciones.objects.filter(evento=evento, alumno=alumno).exists():
            return Response({"detail": "El alumno ya está inscrito o en lista de espera", "estado": "ya_inscrito"}, status=400)

        inscripcion = Inscripciones.objects.create(
            evento=evento, alumno=alumno, tipo='lista_espera'
        )
        data = InscripcionSerializer(inscripcion).data
        data['estado'] = 'lista_espera'
        return Response(data, status=status.HTTP_201_CREATED)


class InscripcionesCancel(generics.CreateAPIView):
    """DELETE /inscripciones/cancel/?evento_id={id}&alumno_id={id}  → cancelar inscripción"""
    permission_classes = (permissions.IsAuthenticated,)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        evento_id = request.GET.get("evento_id")
        alumno_id = request.GET.get("alumno_id")

        if not evento_id or not alumno_id:
            return Response({"details": "evento_id y alumno_id son requeridos"}, status=400)

        inscripcion = Inscripciones.objects.select_for_update().filter(evento_id=evento_id, alumno_id=alumno_id).first()
        if not inscripcion:
            return Response({"details": "Inscripción no encontrada"}, status=404)

        tipo_anterior = inscripcion.tipo
        try:
            inscripcion.delete()
        except Exception:
            logger.exception(
                "Error canceling inscripcion evento_id=%s alumno_id=%s by user_id=%s",
                evento_id,
                alumno_id,
                getattr(request.user, 'id', None),
            )
            return Response({"detail": "Error al cancelar inscripción"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Si era inscrito y hay lista de espera, promover al primero
        if tipo_anterior == 'inscrito':
            siguiente = (
                Inscripciones.objects.select_for_update()
                .filter(evento_id=evento_id, tipo='lista_espera')
                .order_by("creation")
                .first()
            )
            if siguiente:
                siguiente.tipo = 'inscrito'
                try:
                    siguiente.save()
                except Exception:
                    logger.exception(
                        "Error promoting waitlist evento_id=%s after cancel by user_id=%s",
                        evento_id,
                        getattr(request.user, 'id', None),
                    )
                    return Response({"detail": "Error al promover lista de espera"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                return Response({"details": "Inscripción cancelada"}, status=status.HTTP_200_OK)

        return Response({"details": "Inscripción cancelada"}, status=status.HTTP_200_OK)
