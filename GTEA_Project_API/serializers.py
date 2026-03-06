from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Administradores, Alumnos, Organizadores, Categorias, Sedes, Aulas, Eventos, Inscripciones


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    rol = serializers.CharField(write_only=True, required=False)
    username = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name", "password", "rol")

    def validate(self, data):
        # Ensure username exists (use email as username if missing)
        if not data.get('username') and data.get('email'):
            data['username'] = data.get('email')

        # Validate unique email for creation
        email = data.get('email')
        if email and User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': ['Este email ya está registrado.']})

        return data

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user


class AdminSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Administradores
        fields = ("id", "user", "clave_admin", "creation", "update", "first_name", "last_name", "email")


class AlumnoSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Alumnos
        fields = ("id", "user", "matricula", "ocupacion", "creation", "update", "first_name", "last_name", "email")


class OrganizadorSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source="user.first_name", read_only=True)
    last_name = serializers.CharField(source="user.last_name", read_only=True)
    email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = Organizadores
        fields = ("id", "user", "id_trabajador", "creation", "update", "first_name", "last_name", "email")


# ═══════════════════════════════════════════════════════════════
# Serializers de dominio: Categorías, Sedes, Aulas, Eventos, Inscripciones
# ═══════════════════════════════════════════════════════════════

class CategoriaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Categorias
        fields = ("id", "nombre", "descripcion", "icon", "color", "activa", "creation", "update")


class SedeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sedes
        fields = ("id", "nombre", "domicilio", "telefono", "email", "pisos", "notas", "instalaciones", "activa", "creation", "update")


class AulaSerializer(serializers.ModelSerializer):
    sede_nombre = serializers.CharField(source="sede.nombre", read_only=True)

    class Meta:
        model = Aulas
        fields = ("id", "sede", "sede_nombre", "nombre", "capacidad", "piso", "tipo", "estado", "creation", "update")


class EventoSerializer(serializers.ModelSerializer):
    categoria_nombre = serializers.CharField(source="categoria.nombre", read_only=True, default='')
    sede_nombre = serializers.CharField(source="sede.nombre", read_only=True, default='')
    aula_nombre = serializers.CharField(source="aula.nombre", read_only=True, default='')
    organizador_nombre = serializers.SerializerMethodField()
    inscritos = serializers.IntegerField(read_only=True)
    imagen_portada = serializers.URLField(required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = Eventos
        fields = (
            "id", "titulo", "categoria", "categoria_nombre", "descripcion", "imagen_portada",
            "fecha_inicio", "hora_inicio", "fecha_fin", "hora_fin",
            "modalidad", "sede", "sede_nombre", "aula", "aula_nombre",
            "cupo_maximo", "costo_entrada", "lista_espera",
            "publicar_inmediatamente", "es_organizador", "organizador", "organizador_nombre",
            "status", "inscritos", "creation", "update",
        )

    def get_organizador_nombre(self, obj):
        if obj.organizador:
            return f"{obj.organizador.first_name} {obj.organizador.last_name}"
        return ''


class InscripcionSerializer(serializers.ModelSerializer):
    alumno_nombre = serializers.SerializerMethodField()
    evento_titulo = serializers.CharField(source="evento.titulo", read_only=True)

    class Meta:
        model = Inscripciones
        fields = ("id", "evento", "evento_titulo", "alumno", "alumno_nombre", "tipo", "creation")

    def get_alumno_nombre(self, obj):
        if obj.alumno and obj.alumno.user:
            return f"{obj.alumno.user.first_name} {obj.alumno.user.last_name}"
        return ''
