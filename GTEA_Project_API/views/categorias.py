from django.db import transaction
from ..authentication import DEFAULT_API_AUTH
from ..serializers import CategoriaSerializer
from ..models import Categorias
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
import logging

logger = logging.getLogger(__name__)


class CategoriasListCreate(generics.ListCreateAPIView):
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Categorias.objects.filter(activa=True).order_by('nombre')
    serializer_class = CategoriaSerializer


class CategoriasAll(generics.CreateAPIView):
    """GET /lista-categorias/  → lista de categorías"""
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        categorias = Categorias.objects.filter(activa=True).order_by("nombre")
        lista = CategoriaSerializer(categorias, many=True).data
        return Response(lista, 200)


class CategoriasView(generics.CreateAPIView):
    """GET /categoria/?id={id}  → obtener categoría por ID
       POST /categoria/         → crear categoría
    """
    authentication_classes = DEFAULT_API_AUTH

    def get(self, request, *args, **kwargs):
        categoria = get_object_or_404(Categorias, id=request.GET.get("id"))
        data = CategoriaSerializer(categoria, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = CategoriaSerializer(data=request.data)
        if serializer.is_valid():
            categoria = Categorias.objects.create(**serializer.validated_data)
            categoria.save()
            return Response({"categoria_created_id": categoria.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CategoriasViewEdit(generics.CreateAPIView):
    """PUT    /categorias-edit/  → editar categoría
       DELETE /categorias-edit/?id={id}  → eliminar categoría
    """
    authentication_classes = DEFAULT_API_AUTH
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        categoria = get_object_or_404(Categorias, id=request.data["id"])
        categoria.nombre = request.data.get("nombre", categoria.nombre)
        categoria.descripcion = request.data.get("descripcion", categoria.descripcion)
        categoria.icon = request.data.get("icon", categoria.icon)
        categoria.color = request.data.get("color", categoria.color)
        categoria.save()
        data = CategoriaSerializer(categoria, many=False).data
        return Response(data, 200)

    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        categoria = get_object_or_404(Categorias, id=request.GET.get("id"))
        try:
            categoria.delete()
            return Response({"details": "Categoría eliminada"}, status=status.HTTP_200_OK)
        except Exception:
            logger.exception("Error deleting categoria id=%s by user_id=%s", request.GET.get("id"), getattr(request.user, 'id', None))
            return Response({"details": "Algo pasó al eliminar"}, status=status.HTTP_200_OK)
