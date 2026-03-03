from ..models import Eventos, Inscripciones, Categorias, Sedes, Alumnos
from rest_framework import permissions, generics
from rest_framework.response import Response
from django.db.models import Count, Q
import logging

logger = logging.getLogger(__name__)


class ReportesResumen(generics.CreateAPIView):
    """GET /reportes/resumen/  → métricas generales para dashboard de reportes"""
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        total_eventos = Eventos.objects.count()
        eventos_activos = Eventos.objects.filter(status='Activo').count()
        eventos_finalizados = Eventos.objects.filter(status='Finalizado').count()
        eventos_cancelados = Eventos.objects.filter(status='Cancelado').count()
        eventos_borrador = Eventos.objects.filter(status='Borrador').count()

        total_inscripciones = Inscripciones.objects.filter(tipo='inscrito').count()
        total_lista_espera = Inscripciones.objects.filter(tipo='lista_espera').count()

        total_categorias = Categorias.objects.filter(activa=True).count()
        total_sedes = Sedes.objects.filter(activa=True).count()
        total_alumnos = Alumnos.objects.filter(user__is_active=True).count()

        # Inscripciones por categoría
        por_categoria = list(
            Inscripciones.objects.filter(tipo='inscrito')
            .values(categoria_nombre=Q(evento__categoria__nombre) if False else None)
            .annotate(count=Count('id'))
            .order_by('-count')
        ) if False else []

        # Hacerlo correctamente
        categorias_stats = list(
            Categorias.objects.filter(activa=True).annotate(
                total_eventos=Count('eventos'),
                total_inscritos=Count('eventos__inscripciones', filter=Q(eventos__inscripciones__tipo='inscrito')),
            ).values('id', 'nombre', 'total_eventos', 'total_inscritos').order_by('-total_inscritos')
        )

        # Eventos con más inscripciones (top 10)
        top_eventos = list(
            Eventos.objects.annotate(
                total_inscritos=Count('inscripciones', filter=Q(inscripciones__tipo='inscrito')),
                total_espera=Count('inscripciones', filter=Q(inscripciones__tipo='lista_espera')),
            ).values('id', 'titulo', 'cupo_maximo', 'total_inscritos', 'total_espera', 'status')
            .order_by('-total_inscritos')[:10]
        )

        # Ocupación por sede
        sedes_stats = list(
            Sedes.objects.filter(activa=True).annotate(
                total_eventos=Count('eventos'),
                total_inscritos=Count('eventos__inscripciones', filter=Q(eventos__inscripciones__tipo='inscrito')),
            ).values('id', 'nombre', 'total_eventos', 'total_inscritos').order_by('-total_inscritos')
        )

        return Response({
            'totales': {
                'eventos': total_eventos,
                'eventos_activos': eventos_activos,
                'eventos_finalizados': eventos_finalizados,
                'eventos_cancelados': eventos_cancelados,
                'eventos_borrador': eventos_borrador,
                'inscripciones': total_inscripciones,
                'lista_espera': total_lista_espera,
                'categorias': total_categorias,
                'sedes': total_sedes,
                'alumnos': total_alumnos,
            },
            'por_categoria': categorias_stats,
            'top_eventos': top_eventos,
            'por_sede': sedes_stats,
        }, 200)
