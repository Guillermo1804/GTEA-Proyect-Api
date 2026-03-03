from django.db import transaction
from ..serializers import SedeSerializer, AulaSerializer
from ..models import Sedes, Aulas
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging
from ..permissions import IsAdminOrReadOnly, IsAdminOrAuthenticated

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════
# SEDES
# ═══════════════════════════════════════════════

class SedesAll(generics.CreateAPIView):
    """GET  /sedes/  → lista de sedes activas
       POST /sedes/  → crear nueva sede
    """
    permission_classes = (IsAdminOrReadOnly,)

    def get(self, request, *args, **kwargs):
        sedes = Sedes.objects.filter(activa=True).order_by("nombre")
        lista = SedeSerializer(sedes, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = SedeSerializer(data=request.data)
        if serializer.is_valid():
            sede = serializer.save()
            return Response({"sede_created_id": sede.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SedesDetail(generics.CreateAPIView):
    """GET /sedes/detail/?id={id}  → obtener sede por ID"""
    permission_classes = (IsAdminOrReadOnly,)

    def get(self, request, *args, **kwargs):
        sede = get_object_or_404(Sedes, id=request.GET.get("id"))
        data = SedeSerializer(sede, many=False).data
        return Response(data, 200)


class SedesEdit(generics.CreateAPIView):
    """PUT    /sedes/edit/?id={id}  → editar sede
       DELETE /sedes/edit/?id={id}  → desactivar sede (soft delete)
    """
    permission_classes = (IsAdminOrReadOnly,)

    def put(self, request, *args, **kwargs):
        sede = get_object_or_404(Sedes, id=request.data.get("id") or request.GET.get("id"))
        sede.nombre = request.data.get("nombre", sede.nombre)
        sede.domicilio = request.data.get("domicilio", sede.domicilio)
        sede.telefono = request.data.get("telefono", sede.telefono)
        sede.email = request.data.get("email", sede.email)
        sede.pisos = request.data.get("pisos", sede.pisos)
        sede.notas = request.data.get("notas", sede.notas)
        if "instalaciones" in request.data:
            sede.instalaciones = request.data["instalaciones"]
        if "activa" in request.data:
            sede.activa = request.data["activa"]
        sede.save()
        data = SedeSerializer(sede, many=False).data
        return Response(data, 200)

    def delete(self, request, *args, **kwargs):
        sede = get_object_or_404(Sedes, id=request.GET.get("id"))
        try:
            sede.activa = False
            sede.save()
            return Response({"details": "Sede desactivada"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})


# ═══════════════════════════════════════════════
# AULAS
# ═══════════════════════════════════════════════

class AulasAll(generics.CreateAPIView):
    """GET  /aulas/?sede_id={id}  → lista de aulas (filtro opcional por sede)
       POST /aulas/               → crear nueva aula
    """
    permission_classes = (IsAdminOrAuthenticated,)

    def get(self, request, *args, **kwargs):
        sede_id = request.GET.get("sede_id")
        qs = Aulas.objects.all().order_by("nombre")
        if sede_id:
            qs = qs.filter(sede_id=sede_id)
        lista = AulaSerializer(qs, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        # El frontend envía sedeId (camelCase); mapeamos a sede (FK)
        data = request.data.copy() if hasattr(request.data, 'copy') else dict(request.data)
        if 'sedeId' in data and 'sede' not in data:
            data['sede'] = data.pop('sedeId')
        serializer = AulaSerializer(data=data)
        if serializer.is_valid():
            aula = serializer.save()
            return Response({"aula_created_id": aula.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AulasEdit(generics.CreateAPIView):
    """PUT    /aulas/edit/?id={id}  → editar aula
       DELETE /aulas/edit/?id={id}  → eliminar aula
    """
    permission_classes = (IsAdminOrAuthenticated,)

    def put(self, request, *args, **kwargs):
        aula = get_object_or_404(Aulas, id=request.data.get("id") or request.GET.get("id"))
        aula.nombre = request.data.get("nombre", aula.nombre)
        aula.capacidad = request.data.get("capacidad", aula.capacidad)
        aula.piso = request.data.get("piso", aula.piso)
        aula.tipo = request.data.get("tipo", aula.tipo)
        aula.estado = request.data.get("estado", aula.estado)
        if "sedeId" in request.data:
            aula.sede_id = request.data["sedeId"]
        elif "sede" in request.data:
            aula.sede_id = request.data["sede"]
        aula.save()
        data = AulaSerializer(aula, many=False).data
        return Response(data, 200)

    def delete(self, request, *args, **kwargs):
        aula = get_object_or_404(Aulas, id=request.GET.get("id"))
        try:
            aula.delete()
            return Response({"details": "Aula eliminada"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})
