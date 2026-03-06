from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth.models import AbstractUser, User
from django.conf import settings

class BearerTokenAuthentication(TokenAuthentication):
    keyword = u"Bearer"


class Administradores(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False, blank=False, default=None)
    clave_admin = models.CharField(max_length=255,null=True, blank=True)
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "Perfil del admin "+self.first_name+" "+self.last_name

class Alumnos(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False, blank=False, default=None)
    matricula = models.CharField(max_length=255,null=True, blank=True)
    ocupacion = models.CharField(max_length=255,null=True, blank=True)
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "Perfil del alumno "+self.first_name+" "+self.last_name

class Organizadores(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False, blank=False, default=None)
    id_trabajador = models.CharField(max_length=255,null=True, blank=True)
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return "Perfil del maestro "+self.first_name+" "+self.last_name


# ═══════════════════════════════════════════════════════════════
# Modelos de dominio: Categorías, Sedes, Aulas, Eventos, Inscripciones
# ═══════════════════════════════════════════════════════════════

class Categorias(models.Model):
    id = models.BigAutoField(primary_key=True)
    nombre = models.CharField(max_length=120)
    descripcion = models.TextField(blank=True, default='')
    icon = models.CharField(max_length=100, blank=True, default='')
    color = models.CharField(max_length=30, blank=True, default='')
    activa = models.BooleanField(default=True)
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.nombre


class Sedes(models.Model):
    id = models.BigAutoField(primary_key=True)
    nombre = models.CharField(max_length=200)
    domicilio = models.TextField(blank=True, default='')
    telefono = models.CharField(max_length=30, blank=True, default='')
    email = models.EmailField(blank=True, default='')
    pisos = models.IntegerField(default=1)
    notas = models.TextField(blank=True, default='')
    instalaciones = models.JSONField(default=list, blank=True)
    activa = models.BooleanField(default=True)
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.nombre


class Aulas(models.Model):
    ESTADO_CHOICES = [
        ('disponible', 'Disponible'),
        ('en-uso', 'En uso'),
        ('mantenimiento', 'Mantenimiento'),
    ]
    id = models.BigAutoField(primary_key=True)
    sede = models.ForeignKey(Sedes, on_delete=models.CASCADE, related_name='aulas')
    nombre = models.CharField(max_length=200)
    capacidad = models.IntegerField(default=30)
    piso = models.IntegerField(default=1)
    tipo = models.CharField(max_length=100, blank=True, default='')
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default='disponible')
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return f"{self.nombre} ({self.sede.nombre})"


class Eventos(models.Model):
    MODALIDAD_CHOICES = [
        ('Presencial', 'Presencial'),
        ('Virtual', 'Virtual'),
    ]
    STATUS_CHOICES = [
        ('Activo', 'Activo'),
        ('Borrador', 'Borrador'),
        ('Finalizado', 'Finalizado'),
        ('Cancelado', 'Cancelado'),
    ]
    id = models.BigAutoField(primary_key=True)
    titulo = models.CharField(max_length=200)
    categoria = models.ForeignKey(Categorias, on_delete=models.SET_NULL, null=True, blank=True, related_name='eventos')
    descripcion = models.TextField(blank=True, default='')
    imagen_portada = models.URLField(blank=True, default='')
    fecha_inicio = models.DateField()
    hora_inicio = models.TimeField()
    fecha_fin = models.DateField()
    hora_fin = models.TimeField()
    modalidad = models.CharField(max_length=20, choices=MODALIDAD_CHOICES, default='Presencial')
    sede = models.ForeignKey(Sedes, on_delete=models.SET_NULL, null=True, blank=True, related_name='eventos')
    aula = models.ForeignKey(Aulas, on_delete=models.SET_NULL, null=True, blank=True, related_name='eventos')
    cupo_maximo = models.IntegerField(default=30)
    costo_entrada = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    lista_espera = models.BooleanField(default=False)
    publicar_inmediatamente = models.BooleanField(default=True)
    es_organizador = models.BooleanField(default=True)
    organizador = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='eventos_organizados')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Borrador')
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    update = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.titulo

    @property
    def inscritos(self):
        return self.inscripciones.filter(tipo='inscrito').count()


class Inscripciones(models.Model):
    TIPO_CHOICES = [
        ('inscrito', 'Inscrito'),
        ('lista_espera', 'Lista de espera'),
    ]
    id = models.BigAutoField(primary_key=True)
    evento = models.ForeignKey(Eventos, on_delete=models.CASCADE, related_name='inscripciones')
    alumno = models.ForeignKey(Alumnos, on_delete=models.CASCADE, related_name='inscripciones')
    tipo = models.CharField(max_length=20, choices=TIPO_CHOICES, default='inscrito')
    creation = models.DateTimeField(auto_now_add=True, null=True, blank=True)

    class Meta:
        unique_together = ('evento', 'alumno')

    def __str__(self):
        return f"{self.alumno} - {self.evento} ({self.tipo})"