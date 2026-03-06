<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Django-6.0-092E20?style=for-the-badge&logo=django&logoColor=white" alt="Django">
  <img src="https://img.shields.io/badge/DRF-3.16-A30000?style=for-the-badge&logo=django&logoColor=white" alt="DRF">
  <img src="https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white" alt="MySQL">
  <img src="https://img.shields.io/badge/Auth-Token-FF6F00?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="Token Auth">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

# 🎓 GTEA — API Backend

> **Gestor de Talleres y Eventos Académicos**
> API RESTful para la administración de sedes, aulas, eventos/talleres y gestión de usuarios por roles.

---

## 📋 Descripción del Proyecto

**GTEA** (Gestor de Talleres y Eventos Académicos) es una plataforma integral diseñada para instituciones educativas que necesitan administrar de forma centralizada:

| Dominio          | Descripción                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **Usuarios**     | Registro con asignación automática de rol según dominio de email            |
| **Sedes & Aulas**| Gestión de instalaciones físicas con relación jerárquica (Sede → Aulas)     |
| **Eventos**      | Creación de talleres/eventos con cupo, modalidad, fechas y categorización   |
| **Inscripciones**| Inscription con **lógica de lista de espera** automática por cupo           |
| **Reportes**     | Dashboard de métricas y resúmenes del sistema                               |

### Roles del Sistema

| Rol              | Clave de acceso                   | Capacidades principales                        |
|------------------|-----------------------------------|-------------------------------------------------|
| 🔴 Administrador | `clave_admin`                     | CRUD total, gestión de usuarios, reportes       |
| 🟡 Organizador   | `id_trabajador`                   | Crear/editar eventos, ver inscripciones         |
| 🟢 Alumno        | `matricula`                       | Inscribirse a eventos, ver catálogo             |

> [!IMPORTANT]
> El rol se asigna **automáticamente** mediante un `switch` que evalúa el dominio del email al registrarse. No existe selección manual de rol en la UI.

---

## 🛠️ Stack Tecnológico

```
Backend Framework   →  Django 6.0.2
API Layer           →  Django REST Framework 3.16.1
Base de Datos       →  MySQL 8.0 (via mysqlclient)
Autenticación       →  Token Authentication (rest_framework.authtoken)
CORS                →  django-cors-headers 4.9.0
Filtrado            →  django-filter 25.2
Servidor WSGI       →  Gunicorn (producción) / manage.py runserver (desarrollo)
```

### Dependencias Principales (`requirements.txt`)

```text
Django==6.0.2
djangorestframework==3.16.1
django-cors-headers==4.9.0
django-filter==25.2
mysqlclient==2.2.8
```

---

## ⚙️ Configuración del Entorno Local

### Prerrequisitos

- **Python** 3.12+
- **MySQL** 8.0+ (o XAMPP con MySQL/MariaDB)
- **Git**

### 1. Clonar el Repositorio

```bash
git clone https://github.com/tu-organizacion/GTEA-Proyect-Api.git
cd GTEA-Proyect-Api
```

### 2. Crear y Activar Entorno Virtual

```bash
# Crear el entorno
python -m venv .venv

# Activar (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Activar (Windows CMD)
.\.venv\Scripts\activate.bat

# Activar (macOS / Linux)
source .venv/bin/activate
```

### 3. Instalar Dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar la Base de Datos

Crea la base de datos en MySQL antes de migrar:

```sql
CREATE DATABASE gtea_proyecto_api CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Verifica que las credenciales en `GTEA_Project_API/settings.py` coincidan con tu entorno local:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'gtea_proyecto_api',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': '127.0.0.1',
        'PORT': '3307',          # Ajusta al puerto de tu MySQL
    }
}
```

### 5. Ejecutar Migraciones

```bash
python manage.py migrate
```

### 6. Crear un Superusuario

```bash
python manage.py createsuperuser
```

### 7. Correr el Servidor de Desarrollo

```bash
python manage.py runserver 8000
```

✅ El servidor estará disponible en `http://127.0.0.1:8000/`

---

## 🔐 Arquitectura de Autenticación

El backend utiliza **Token Authentication** de DRF. Todos los endpoints (excepto login y registro) están protegidos y requieren un token válido.

### Flujo de Autenticación

```
┌──────────┐       POST /auth/login/         ┌──────────┐
│  Client  │  ─────────────────────────────► │  Server  │
│ (Angular)│  { username, password }         │ (Django) │
│          │  ◄───────────────────────────── │          │
│          │  { token: "abc123...",          │          │
│          │    user_id, role, ... }         │          │
└──────────┘                                 └──────────┘
```

### Header Requerido en Peticiones Protegidas

```http
Authorization: Token <tu_token>
```

### Endpoints de Autenticación

| Método | Endpoint         | Descripción                              | Auth  |
|--------|------------------|------------------------------------------|-------|
| POST   | `/auth/login/`   | Obtener token con credenciales           | ❌   |
| POST   | `/auth/logout/`  | Invalidar token activo                   | ✅   |
| POST   | `/users/register/`| Registro de nuevo usuario (rol automático)| ❌ |

> [!NOTE]
> El login retorna el token junto con información del usuario como `user_id`, `role`, `first_name`, `last_name` y `email`.

---

## 🗺️ Mapeo de Entidades Principales (API Overview)

### Usuarios & Roles

| Método | Endpoint              | Descripción                          |
|--------|-----------------------|--------------------------------------|
| GET    | `/admins/`            | Listar todos los administradores     |
| GET    | `/admins/detail/`     | Detalle de un administrador          |
| PUT    | `/admins/edit/`       | Editar un administrador              |
| GET    | `/organizadores/`     | Listar todos los organizadores       |
| GET    | `/organizadores/detail/` | Detalle de un organizador         |
| PUT    | `/organizadores/edit/`| Editar un organizador                |
| GET    | `/alumnos/`           | Listar todos los alumnos             |
| GET    | `/alumnos/detail/`    | Detalle de un alumno                 |
| PUT    | `/alumnos/edit/`      | Editar un alumno                     |

### Sedes & Aulas

Relación: **Sede `1 ── ∞` Aulas**

| Método | Endpoint          | Descripción                           |
|--------|-------------------|---------------------------------------|
| GET    | `/sedes/`         | Listar todas las sedes                |
| GET    | `/sedes/detail/`  | Detalle de una sede (incluye aulas)   |
| PUT    | `/sedes/edit/`    | Crear / Editar una sede               |
| GET    | `/aulas/`         | Listar todas las aulas                |
| PUT    | `/aulas/edit/`    | Crear / Editar un aula                |

> **Modelo `Aulas`:** Cada aula tiene un `estado` con opciones: `disponible`, `en-uso`, `mantenimiento`.

### Categorías

| Método | Endpoint              | Descripción                       |
|--------|-----------------------|-----------------------------------|
| GET    | `/categorias/`        | Listar todas las categorías       |
| GET    | `/categorias/detail/` | Detalle de una categoría          |
| PUT    | `/categorias/edit/`   | Crear / Editar una categoría      |

### Eventos

| Método | Endpoint            | Descripción                          |
|--------|---------------------|--------------------------------------|
| GET    | `/eventos/`         | Listar todos los eventos             |
| GET    | `/eventos/detail/`  | Detalle de un evento (con inscritos) |
| PUT    | `/eventos/edit/`    | Crear / Editar un evento             |

**Campos clave del modelo `Eventos`:**

```
titulo, categoria, descripcion, imagen_portada,
fecha_inicio, hora_inicio, fecha_fin, hora_fin,
modalidad (Presencial | Virtual),
sede, aula, cupo_maximo, costo_entrada,
lista_espera (bool), status (Activo | Borrador | Finalizado | Cancelado),
organizador (FK → User)
```

### Inscripciones ⚡

> [!CAUTION]
> **Lógica crítica de negocio.** La inscripción maneja automáticamente cupo regular vs. lista de espera. Si el cupo está lleno, el backend retorna `409 Conflict` y registra al alumno en la lista de espera.

| Método | Endpoint                       | Descripción                                     |
|--------|--------------------------------|-------------------------------------------------|
| POST   | `/inscripciones/`              | Inscribir alumno (o enviar a lista de espera)   |
| GET    | `/inscripciones/lista-espera/` | Ver alumnos en lista de espera                  |
| POST   | `/inscripciones/cancel/`       | Cancelar inscripción de un alumno               |

**Flujo de inscripción:**

```
Alumno solicita inscribirse
        │
        ▼
  ¿Cupo disponible?
   /           \
  SÍ            NO
  │              │
  ▼              ▼
Inscrito     Lista de espera
(tipo:       (tipo:
 'inscrito')  'lista_espera')
              + HTTP 409
```

**Constraint:** `unique_together = ('evento', 'alumno')` — **un alumno no puede inscribirse dos veces al mismo evento.**

### Reportes

| Método | Endpoint              | Descripción                           |
|--------|-----------------------|---------------------------------------|
| GET    | `/reportes/resumen/`  | Resumen con métricas generales del sistema |

---

## 📊 Diagrama Entidad-Relación

```
┌──────────┐       ┌──────────────┐       ┌──────────────┐
│   User   │◄──FK──│ Administrador│       │  Categorías  │
│ (Django) │       └──────────────┘       └──────┬───────┘
│          │       ┌──────────────┐              │ FK
│          │◄──FK──│ Organizador  │              │
│          │       └──────────────┘       ┌──────▼───────┐
│          │       ┌──────────────┐   FK  │   Eventos    │◄──┐
│          │◄──FK──│   Alumnos    │──────►│              │   │
│          │       └──────┬───────┘       │  cupo_maximo │   │
└──────────┘              │               │  inscritos   │   │
                          │               └──────────────┘   │
                          │                                  │
                   ┌──────▼───────┐    ┌──────────┐   FK     │
                   │Inscripciones │    │  Sedes   │──────────┘
                   │              │    │          │
                   │ tipo:        │    └────┬─────┘
                   │  inscrito    │         │ 1:N
                   │  lista_espera│    ┌────▼─────┐
                   └──────────────┘    │  Aulas   │──FK──► Eventos
                                       └──────────┘
```

---

## 🌿 Flujo de Trabajo (Git)

### Convención de Ramas

```bash
# Crear una rama para una nueva característica
git checkout -b feature/nombre-de-la-feature

# Crear una rama para un bugfix
git checkout -b fix/descripcion-del-bug

# Crear una rama para hotfix en producción
git checkout -b hotfix/descripcion-critica
```

### Flujo Recomendado

```bash
# 1. Sincronizar con la rama principal
git checkout main
git pull origin main

# 2. Crear tu rama de trabajo
git checkout -b feature/mi-nueva-feature

# 3. Hacer commits descriptivos
git add .
git commit -m "feat(eventos): agregar validación de cupo máximo"

# 4. Subir tu rama al remoto
git push origin feature/mi-nueva-feature

# 5. Abrir un Pull Request para revisión
```

### Convención de Commits

| Prefijo      | Uso                              |
|--------------|----------------------------------|
| `feat()`     | Nueva funcionalidad              |
| `fix()`      | Corrección de bug                |
| `refactor()` | Refactorización sin cambio lógico|
| `docs()`     | Cambios en documentación         |
| `test()`     | Agregar o corregir tests         |
| `chore()`    | Tareas de mantenimiento          |

---

## 📁 Estructura del Proyecto

```
GTEA-Proyect-Api/
├── manage.py                    # Entry point de Django
├── requirements.txt             # Dependencias de Python
├── README.md                    # Este archivo
│
└── GTEA_Project_API/
    ├── __init__.py
    ├── settings.py              # Configuración de Django (DB, CORS, DRF)
    ├── urls.py                  # Mapeo central de rutas
    ├── wsgi.py                  # Despliegue WSGI
    ├── asgi.py                  # Despliegue ASGI
    ├── models.py                # Modelos ORM (Usuarios, Sedes, Eventos, etc.)
    ├── serializers.py           # Serializadores DRF
    ├── permissions.py           # Permisos personalizados por rol
    ├── admin.py                 # Configuración del admin de Django
    ├── migrations/              # Migraciones de la base de datos
    ├── management/              # Comandos personalizados de manage.py
    └── views/                   # Vistas de la API (organizadas por dominio)
        ├── auth.py              # Login / Logout
        ├── users.py             # Registro y gestión de admins
        ├── alumnos.py           # CRUD de alumnos
        ├── organizador.py       # CRUD de organizadores
        ├── categorias.py        # CRUD de categorías
        ├── sedes.py             # CRUD de sedes y aulas
        ├── eventos.py           # CRUD de eventos
        ├── inscripciones.py     # Inscripciones y lista de espera
        └── reportes.py          # Reportes y métricas
```

---

## 🤝 Equipo & Contacto

**Proyecto:** GTEA — Gestor de Talleres y Eventos Académicos
**Materia:** Modelos de Desarrollo Web
**Stack Frontend:** Angular 20 · TypeScript · SCSS

---

<p align="center">
  <sub>Built with ❤️ using Django REST Framework</sub>
</p>