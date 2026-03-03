from django.db import transaction
from ..serializers import CategoriaSerializer
from ..models import Categorias
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging

logger = logging.getLogger(__name__)


class CategoriasAll(generics.CreateAPIView):
    """GET  /categorias/  → lista de categorías activas
       POST /categorias/  → crear nueva categoría
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        categorias = Categorias.objects.filter(activa=True).order_by("nombre")
        lista = CategoriaSerializer(categorias, many=True).data
        return Response(lista, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = CategoriaSerializer(data=request.data)
        if serializer.is_valid():
            categoria = serializer.save()
            return Response({"categoria_created_id": categoria.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CategoriasDetail(generics.CreateAPIView):
    """GET /categorias/detail/?id={id}  → obtener categoría por ID"""
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        categoria = get_object_or_404(Categorias, id=request.GET.get("id"))
        data = CategoriaSerializer(categoria, many=False).data
        return Response(data, 200)


class CategoriasEdit(generics.CreateAPIView):
    """PUT    /categorias/edit/?id={id}  → editar categoría
       DELETE /categorias/edit/?id={id}  → desactivar categoría (soft delete)
    """
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        categoria = get_object_or_404(Categorias, id=request.data.get("id") or request.GET.get("id"))
        categoria.nombre = request.data.get("nombre", categoria.nombre)
        categoria.descripcion = request.data.get("descripcion", categoria.descripcion)
        categoria.icon = request.data.get("icon", categoria.icon)
        categoria.color = request.data.get("color", categoria.color)
        if "activa" in request.data:
            categoria.activa = request.data["activa"]
        categoria.save()
        data = CategoriaSerializer(categoria, many=False).data
        return Response(data, 200)

    def delete(self, request, *args, **kwargs):
        categoria = get_object_or_404(Categorias, id=request.GET.get("id"))
        try:
            categoria.activa = False
            categoria.save()
            return Response({"details": "Categoría desactivada"})
        except Exception as e:
            return Response({"details": "Algo pasó al eliminar"})
