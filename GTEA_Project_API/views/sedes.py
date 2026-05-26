from django.db import transaction
from ..authentication import DEFAULT_API_AUTH
from ..serializers import SedeSerializer, AulaSerializer
from ..models import Sedes, Aulas
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging

logger = logging.getLogger(__name__)


def _normalize_aula_payload(data: dict) -> dict:
    mapping = {
        'sedeId': 'sede',
    }

    for camel_key, snake_key in mapping.items():
        if snake_key not in data and camel_key in data:
            data[snake_key] = data[camel_key]
    return data


# ═══════════════════════════════════════════════
# SEDES
# ═══════════════════════════════════════════════


class SedesListCreate(generics.ListCreateAPIView):
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Sedes.objects.filter(activa=True).order_by('nombre')
    serializer_class = SedeSerializer


class SedesAll(generics.CreateAPIView):
    """GET /lista-sedes/  → lista de sedes"""
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        sedes = Sedes.objects.filter(activa=True).order_by("nombre")
        lista = SedeSerializer(sedes, many=True).data
        return Response(lista, 200)


class SedesView(generics.CreateAPIView):
    """GET /sede/?id={id}  → obtener sede por ID
       POST /sede/         → crear sede
    """
    authentication_classes = DEFAULT_API_AUTH

    def get(self, request, *args, **kwargs):
        sede = get_object_or_404(Sedes, id=request.GET.get("id"))
        data = SedeSerializer(sede, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = SedeSerializer(data=request.data)
        if serializer.is_valid():
            sede = Sedes.objects.create(**serializer.validated_data)
            sede.save()
            return Response({"sede_created_id": sede.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SedesViewEdit(generics.CreateAPIView):
    """PUT    /sedes-edit/      → editar sede
       DELETE /sedes-edit/?id={id}  → eliminar sede
    """
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        sede = get_object_or_404(Sedes, id=request.data["id"])
        sede.nombre = request.data.get("nombre", sede.nombre)
        sede.domicilio = request.data.get("domicilio", sede.domicilio)
        sede.telefono = request.data.get("telefono", sede.telefono)
        sede.email = request.data.get("email", sede.email)
        sede.pisos = request.data.get("pisos", sede.pisos)
        sede.notas = request.data.get("notas", sede.notas)
        if "instalaciones" in request.data:
            sede.instalaciones = request.data["instalaciones"]
        sede.save()
        data = SedeSerializer(sede, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        sede = get_object_or_404(Sedes, id=request.GET.get("id"))
        try:
            sede.delete()
            return Response({"details": "Sede eliminada"}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error deleting sede id=%s by user_id=%s", request.GET.get("id"), getattr(request.user, 'id', None))
            return Response({"details": "Algo pasó al eliminar"}, status=status.HTTP_200_OK)


# ═══════════════════════════════════════════════
# AULAS
# ═══════════════════════════════════════════════

class AulasAll(generics.CreateAPIView):
    """GET /lista-aulas/?sede_id={id}  → lista de aulas (filtro opcional por sede)"""
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        sede_id = request.GET.get("sede_id")
        qs = Aulas.objects.all().order_by("nombre")
        if sede_id:
            qs = qs.filter(sede_id=sede_id)
        lista = AulaSerializer(qs, many=True).data
        return Response(lista, 200)


class AulasView(generics.CreateAPIView):
    """GET /aula/?id={id}  → obtener aula por ID
       POST /aula/         → crear aula
    """

    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        aula_id = request.GET.get("id")
        if aula_id:
            aula = get_object_or_404(Aulas, id=aula_id)
            data = AulaSerializer(aula, many=False).data
            return Response(data, 200)

        sede_id = request.GET.get("sede_id")
        qs = Aulas.objects.all().order_by("nombre")
        if sede_id:
            qs = qs.filter(sede_id=sede_id)
        lista = AulaSerializer(qs, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        data = _normalize_aula_payload(data)
        serializer = AulaSerializer(data=data)
        if serializer.is_valid():
            aula = Aulas.objects.create(**serializer.validated_data)
            aula.save()
            return Response({"aula_created_id": aula.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AulasViewEdit(generics.CreateAPIView):
    """PUT    /aulas-edit/      → editar aula
       DELETE /aulas-edit/?id={id}  → eliminar aula
    """
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        aula = get_object_or_404(Aulas, id=request.data["id"])
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        data = _normalize_aula_payload(data)

        aula.nombre = data.get("nombre", aula.nombre)
        aula.capacidad = data.get("capacidad", aula.capacidad)
        aula.piso = data.get("piso", aula.piso)
        aula.tipo = data.get("tipo", aula.tipo)
        aula.estado = data.get("estado", aula.estado)
        if "sede" in data:
            aula.sede_id = data["sede"]
        aula.save()
        data = AulaSerializer(aula, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        aula = get_object_or_404(Aulas, id=request.GET.get("id"))
        try:
            aula.delete()
            return Response({"details": "Aula eliminada"}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error deleting aula id=%s by user_id=%s", request.GET.get("id"), getattr(request.user, 'id', None))
            return Response({"details": "Algo pasó al eliminar"}, status=status.HTTP_200_OK)
