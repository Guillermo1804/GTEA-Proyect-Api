from django.db import transaction
from ..serializers import InscripcionSerializer
from ..models import Inscripciones, Eventos, Alumnos
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging
from ..permissions import IsAdminOrAuthenticated

logger = logging.getLogger(__name__)


class InscripcionesAll(generics.CreateAPIView):
    """POST /inscripciones/  → inscribirse a un evento"""
    permission_classes = (IsAdminOrAuthenticated,)

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

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        evento_id = request.data.get("evento_id")
        alumno_id = request.data.get("alumno_id")

        if not evento_id or not alumno_id:
            return Response({"detail": "evento_id y alumno_id son requeridos"}, status=400)

        evento = get_object_or_404(Eventos, id=evento_id)
        alumno = get_object_or_404(Alumnos, id=alumno_id)

        # Verificar si ya está inscrito
        if Inscripciones.objects.filter(evento=evento, alumno=alumno).exists():
            return Response({"detail": "El alumno ya está inscrito en este evento", "estado": "ya_inscrito"}, status=400)

        # Verificar cupo
        inscritos = evento.inscripciones.filter(tipo='inscrito').count()
        if inscritos >= evento.cupo_maximo:
            if evento.lista_espera:
                # Inscribir en lista de espera
                inscripcion = Inscripciones.objects.create(
                    evento=evento, alumno=alumno, tipo='lista_espera'
                )
                data = InscripcionSerializer(inscripcion).data
                data['estado'] = 'lista_espera'
                return Response(data, status=status.HTTP_201_CREATED)
            else:
                return Response({"detail": "Evento lleno y sin lista de espera", "estado": "lleno"}, status=400)

        # Inscripción normal
        inscripcion = Inscripciones.objects.create(
            evento=evento, alumno=alumno, tipo='inscrito'
        )
        data = InscripcionSerializer(inscripcion).data
        data['estado'] = 'inscrito'
        return Response(data, status=status.HTTP_201_CREATED)


class InscripcionesListaEspera(generics.CreateAPIView):
    """POST /inscripciones/lista-espera/  → inscribirse a la lista de espera"""
    permission_classes = (IsAdminOrAuthenticated,)

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
    permission_classes = (IsAdminOrAuthenticated,)

    def delete(self, request, *args, **kwargs):
        evento_id = request.GET.get("evento_id")
        alumno_id = request.GET.get("alumno_id")

        if not evento_id or not alumno_id:
            return Response({"detail": "evento_id y alumno_id son requeridos"}, status=400)

        inscripcion = Inscripciones.objects.filter(evento_id=evento_id, alumno_id=alumno_id).first()
        if not inscripcion:
            return Response({"detail": "Inscripción no encontrada"}, status=404)

        tipo_anterior = inscripcion.tipo
        inscripcion.delete()

        # Si era inscrito y hay lista de espera, promover al primero
        if tipo_anterior == 'inscrito':
            siguiente = Inscripciones.objects.filter(
                evento_id=evento_id, tipo='lista_espera'
            ).order_by("creation").first()
            if siguiente:
                siguiente.tipo = 'inscrito'
                siguiente.save()

        return Response({"detail": "Inscripción cancelada", "estado": "cancelado"})
