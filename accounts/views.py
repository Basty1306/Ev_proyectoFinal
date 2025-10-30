# -*- coding: utf-8 -*-
from django.db import connection, IntegrityError
from django.http import HttpResponse
#from reportlab. lib.pagesizes import A4  # Importar e instalar reportlab si no está instalado, seccion de Actas deL arbitro 
from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from django.core.paginator import Paginator
from django.shortcuts import render
from django.core.cache import cache
from django.views.decorators.cache import never_cache, cache_control

from .forms import LoginForm, RegistroUsuarioForm, AsignarRolForm, EditarCargoArbitralForm
from .utils import role_required

import re
import unicodedata
from datetime import date, datetime, time, timedelta

# ============================================================
# Helpers comunes (reutilizables en varios views)
# ============================================================

DIAS_NOMBRES = ["Domingo", "Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado"]

def _normalize_role(s: str) -> str:
    """Lower + remover acentos para comparar roles ('Árbitro' == 'arbitro')."""
    if not s:
        return ""
    s = "".join(c for c in unicodedata.normalize("NFD", s) if unicodedata.category(c) != "Mn")
    return s.strip().lower()

def _parse_rut_from_session(request):
    """Extrae (rut, dv) de session o levanta ValueError."""
    rut_full = request.session.get("user_rut", "")
    rut, dv = rut_full.split("-")
    # normaliza y valida
    rut = str(int(str(rut).replace(".", "").strip()))
    dv = dv.strip().upper()
    return rut, dv

def _valid_hhmm(s: str) -> bool:
    return bool(re.fullmatch(r"^[0-2]\d:[0-5]\d$", s))

def _order_by_time_nulls_last(alias: str = "p") -> str:
    """
    ORDER BY compatible para poner NULL al final sin 'NULLS LAST'.
    Ej.: ORDER BY p.fecha ASC, ({alias}.hora IS NULL) ASC, {alias}.hora ASC
    """
    return f"({alias}.hora IS NULL) ASC, {alias}.hora ASC"


# ============================================================
# LOGIN MANUAL CON SESIÓN
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def login_view(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            rut_input = (form.cleaned_data.get("rut") or "").strip()
            password  = form.cleaned_data.get("contrasena") or ""

            # Normaliza "12.345.678-9"
            rut_limpio = rut_input.replace(".", "").upper()
            if "-" not in rut_limpio:
                messages.error(request, "Formato de RUT inválido. Use 12345678-9.")
                return render(request, "accounts/login.html", {"form": form})

            rut_numero, dv = rut_limpio.split("-", 1)
            rut_numero = rut_numero.strip()
            dv = dv.strip().upper()

            if not rut_numero.isdigit() or not (6 <= len(rut_numero) <= 8) or not (dv.isdigit() or dv == "K"):
                messages.error(request, "RUT/DV inválidos. Use 12345678-9 con DV 0-9 o K.")
                return render(request, "accounts/login.html", {"form": form})

            try:
                rut_int = int(rut_numero)
            except ValueError:
                messages.error(request, "RUT inválido.")
                return render(request, "accounts/login.html", {"form": form})

            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT l.contrasena, l.estado, u.nombre, r.nombre_rol
                          FROM login l
                          JOIN usuarios u 
                            ON u.rut = l.rut AND UPPER(u.digitov) = UPPER(l.digitov)
                     LEFT JOIN usuarios_roles ur 
                            ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
                     LEFT JOIN roles r 
                            ON r.rol_id = ur.rol_id
                         WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
                         LIMIT 1;
                    """, [rut_int, dv])
                    data = cursor.fetchone()
            except Exception:
                messages.error(request, "Error de conexión con la base de datos.")
                return render(request, "accounts/login.html", {"form": form})

            if not data:
                messages.error(request, "RUT o contraseña incorrectos.")
                return render(request, "accounts/login.html", {"form": form})

            contrasena_db, estado, nombre, rol = data
            if password != (contrasena_db or ""):
                messages.error(request, "Contraseña incorrecta.")
                return render(request, "accounts/login.html", {"form": form})

            if _normalize_role(estado) != "activo":
                messages.error(request, "Usuario inactivo.")
                return render(request, "accounts/login.html", {"form": form})

            # sesión limpia
            request.session.flush()
            request.session["user_rut"] = f"{rut_int}-{dv}"
            request.session["user_nombre"] = nombre
            request.session["user_rol"] = rol or "Sin rol"
            rol_norm = _normalize_role(rol or "")
            request.session["user_is_arbitro"] = (rol_norm == "arbitro")
            request.session["BOOT_EPOCH"] = cache.get('BOOT_EPOCH')

            request.session["mostrar_bienvenida"] = True

            if rol_norm == "administrador":
                return redirect(reverse("dashboard"))
            elif rol_norm == "arbitro":
                return redirect(reverse("perfil_arbitro"))
            elif rol_norm == "tribunal de disciplina":
                return redirect(reverse("panel_tribunal"))
            elif rol_norm in ("secretario", "secretaria"):
                return redirect(reverse("panel_secretaria"))
            elif rol_norm == "turno":
                return redirect(reverse("panel_turno"))
            else:
                messages.warning(request, "Tu rol no tiene un panel asignado.")
                return redirect("login")
        else:
            messages.error(request, "Por favor, corrige los errores del formulario.")
    else:
        form = LoginForm()

    return render(request, "accounts/login.html", {"form": form})


# ============================================================
# LOGOUT
# ============================================================

def logout_view(request):
    request.session.flush()
    messages.info(request, "Sesión cerrada correctamente.")
    resp = redirect("login")
    resp["Cache-Control"] = "no-store"
    return resp


# ============================================================
# DASHBOARD (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def dashboard(request):
    if "user_rut" not in request.session:
        return redirect("login")

    user_nombre = request.session.get("user_nombre", "Usuario")
    user_rol = request.session.get("user_rol", "Sin rol")

    with connection.cursor() as cursor:
        # Usuarios con rol ACTIVO
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            WHERE LOWER(ur.estado) = 'activo';
        """)
        usuarios_activos = cursor.fetchone()[0]

        # Usuarios INACTIVOS = sin rol o con rol marcado Inactivo
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            LEFT JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            WHERE ur.rut IS NULL OR LOWER(ur.estado) = 'inactivo';
        """)
        usuarios_inactivos = cursor.fetchone()[0]

        # Administradores con estado ACTIVO
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            JOIN roles r
              ON r.rol_id = ur.rol_id
            WHERE LOWER(r.nombre_rol) = 'administrador'
              AND LOWER(ur.estado) = 'activo';
        """)
        administradores = cursor.fetchone()[0]

        # Árbitros con estado ACTIVO
        cursor.execute("""
            SELECT COUNT(DISTINCT (u.rut, UPPER(u.digitov)))
            FROM usuarios u
            JOIN usuarios_roles ur
              ON ur.rut = u.rut AND UPPER(ur.digitov) = UPPER(u.digitov)
            JOIN roles r
              ON r.rol_id = ur.rol_id
            WHERE LOWER(r.nombre_rol) = 'arbitro'
              AND LOWER(ur.estado) = 'activo';
        """)
        arbitros = cursor.fetchone()[0]

        # Partidos sin árbitro asignado (tu consulta original)
        cursor.execute("""
            SELECT COUNT(*)
            FROM partidos
            WHERE rut IS NULL
               OR digitov IS NULL
               OR TRIM(COALESCE(digitov, '')) = '';
        """)
        partidos_sin_arbitro = cursor.fetchone()[0]

    return render(request, "accounts/dashboard.html", {
        "user_nombre": user_nombre,
        "user_rol": user_rol,
        "usuarios_activos": usuarios_activos,
        "usuarios_inactivos": usuarios_inactivos,
        "administradores": administradores,
        "arbitros": arbitros,
        "partidos_sin_arbitro": partidos_sin_arbitro,
    })


# ============================================================
# REGISTRO DE USUARIO (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def registrar_usuario(request):
    if request.method == "POST":
        form = RegistroUsuarioForm(request.POST)
        if form.is_valid():
            rut_raw = str(form.cleaned_data.get("rut") or "")
            rut_str = rut_raw.replace(".", "").replace("-", "").strip()
            dv      = str(form.cleaned_data.get("digitoV", "") or "").strip().upper()
            correo  = form.cleaned_data.get("correo")

            if not rut_str.isdigit():
                messages.error(request, "El RUT debe contener solo números (sin puntos ni guion).")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            if not (6 <= len(rut_str) <= 8):
                messages.error(request, "El RUT debe tener entre 6 y 8 dígitos.")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            try:
                rut_int = int(rut_str)
            except ValueError:
                messages.error(request, "El RUT ingresado es inválido.")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            if rut_int > 99999999:
                messages.error(request, "El RUT ingresado es inválido.")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            if len(dv) != 1:
                messages.error(request, "El dígito verificador debe ser un solo carácter (0-9 o K).")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT COUNT(*)
                          FROM usuarios
                         WHERE rut = %s AND UPPER(digitov) = UPPER(%s);
                    """, [rut_int, dv])
                    existe_rut_dv = cursor.fetchone()[0] > 0

                    if existe_rut_dv:
                        messages.warning(request, f"⚠️ Ya existe un usuario con el RUT {rut_int}-{dv}.")
                        return render(request, "accounts/registrar_usuario.html", {"form": form})

                    cursor.execute("""
                        SELECT COUNT(*)
                          FROM usuarios
                         WHERE LOWER(correo) = LOWER(%s);
                    """, [correo])
                    existe_correo = cursor.fetchone()[0] > 0

                    if existe_correo:
                        messages.warning(request, f"⚠️ El correo '{correo}' ya está en uso.")
                        return render(request, "accounts/registrar_usuario.html", {"form": form})

                form.save()

                messages.success(request, f"✅ Usuario {rut_int}-{dv} registrado correctamente.")
                return redirect("dashboard")

            except IntegrityError as e:
                constraint = getattr(getattr(e, "__cause__", None), "diag", None)
                cname = getattr(constraint, "constraint_name", "") if constraint else ""
                msg = str(e)

                if "correo" in msg.lower() or "correo" in (cname or "").lower():
                    messages.error(request, f"⚠️ El correo '{correo}' ya está en uso.")
                elif "usuarios_pkey" in (cname or "").lower() or "rut" in msg.lower():
                    messages.error(request, f"⚠️ Ya existe un usuario con el RUT {rut_int} (independiente del DV).")
                else:
                    messages.error(request, f"❌ Error de integridad: {cname or msg}")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

            except Exception as e:
                messages.error(request, f"❌ Error inesperado: {str(e)}")
                return render(request, "accounts/registrar_usuario.html", {"form": form})

        else:
            messages.error(request, "Por favor, corrige los errores del formulario.")
    else:
        form = RegistroUsuarioForm()

    return render(request, "accounts/registrar_usuario.html", {"form": form})


# ============================================================
# ASIGNAR ROL (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def asignar_rol(request):
    """
    Asignar/editar/eliminar rol de los usuarios.
    Valida RUT (6-8 dígitos), DV (1 char) y existencia de usuario/rol.
    """

    # =====================================================
    # POST → procesar formulario (asignar / editar / eliminar)
    # =====================================================
    if request.method == "POST":
        rut_num = (request.POST.get("rut_num") or "").replace(".", "").replace("-", "").strip()
        digitoV = (request.POST.get("digitoV") or "").strip().upper()
        rol_id  = (request.POST.get("rol") or "").strip()
        activo  = (request.POST.get("activo") or "False").strip()

        # --- Validaciones de RUT ---
        if not rut_num.isdigit():
            messages.error(request, "El RUT debe contener solo números (sin puntos ni guion).")
            return redirect("asignar_rol")

        if not (6 <= len(rut_num) <= 8):
            messages.error(request, "El RUT debe tener entre 6 y 8 dígitos.")
            return redirect("asignar_rol")

        if int(rut_num) > 99999999:
            messages.error(request, "El RUT ingresado es inválido.")
            return redirect("asignar_rol")

        if len(digitoV) != 1:
            messages.error(request, "El dígito verificador debe ser un solo carácter (0-9 o K).")
            return redirect("asignar_rol")

        rut_completo = f"{rut_num}-{digitoV}"

        # --- Verificar existencia del usuario ---
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 1
                  FROM usuarios
                 WHERE rut = %s AND UPPER(digitov) = UPPER(%s)
                 LIMIT 1;
            """, [int(rut_num), digitoV])
            existe_usuario = cursor.fetchone() is not None

        if not existe_usuario:
            messages.error(request, f"El usuario con RUT {rut_completo} no existe.")
            return redirect("asignar_rol")

        # --- Procesar rol ---
        es_sin_rol = (rol_id == "0")
        if not es_sin_rol:
            try:
                rol_id_int = int(rol_id)
            except ValueError:
                messages.error(request, "Rol inválido.")
                return redirect("asignar_rol")

            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM roles WHERE rol_id = %s LIMIT 1;", [rol_id_int])
                if cursor.fetchone() is None:
                    messages.error(request, "El rol seleccionado no existe.")
                    return redirect("asignar_rol")

        estado_ur    = "Activo" if activo == "True" else "Inactivo"
        estado_login = "activo" if activo == "True" else "inactivo"

        # --- Actualizar o eliminar rol ---
        with connection.cursor() as cursor:
            if es_sin_rol:
                cursor.execute(
                    "DELETE FROM usuarios_roles WHERE rut = %s AND digitov = %s;",
                    [int(rut_num), digitoV]
                )
                cursor.execute(
                    "UPDATE login SET estado = %s WHERE rut = %s AND digitov = %s;",
                    ["inactivo", int(rut_num), digitoV]
                )
                messages.info(request, f"Se ha removido el rol del usuario {rut_completo}.")
            else:
                cursor.execute(
                    "SELECT 1 FROM usuarios_roles WHERE rut = %s AND digitov = %s LIMIT 1;",
                    [int(rut_num), digitoV]
                )
                if cursor.fetchone():
                    cursor.execute("""
                        UPDATE usuarios_roles
                           SET rol_id = %s, estado = %s
                         WHERE rut = %s AND digitov = %s;
                    """, [rol_id_int, estado_ur, int(rut_num), digitoV])
                else:
                    cursor.execute("""
                        INSERT INTO usuarios_roles (rut, digitov, rol_id, estado)
                        VALUES (%s, %s, %s, %s);
                    """, [int(rut_num), digitoV, rol_id_int, estado_ur])

                cursor.execute(
                    "UPDATE login SET estado = %s WHERE rut = %s AND digitov = %s;",
                    [estado_login, int(rut_num), digitoV]
                )
                messages.success(request, f"Rol actualizado correctamente para {rut_completo}.")

        return redirect("asignar_rol")

    # =====================================================
    # GET → mostrar listado de usuarios (con búsqueda + paginación)
    # =====================================================

    # 🔍 Búsqueda por RUT o nombre / apellido
    busqueda = request.GET.get("q", "").strip()

    query_base = """
        SELECT 
            u.rut, u.nombre, u.apellidop,
            COALESCE(r.nombre_rol, 'Sin rol') AS nombre_rol,
            COALESCE(ur.estado, 'Inactivo')   AS estado,
            u.digitov
        FROM usuarios u
        LEFT JOIN usuarios_roles ur ON u.rut = ur.rut AND u.digitov = ur.digitov
        LEFT JOIN roles r          ON ur.rol_id = r.rol_id
    """

    parametros = []
    if busqueda:
        query_base += """
            WHERE CAST(u.rut AS TEXT) ILIKE %s
               OR UPPER(u.nombre) LIKE UPPER(%s)
               OR UPPER(u.apellidop) LIKE UPPER(%s)
        """
        parametros = [f"%{busqueda}%", f"%{busqueda}%", f"%{busqueda}%"]

    query_base += " ORDER BY u.nombre;"

    with connection.cursor() as cursor:
        cursor.execute(query_base, parametros)
        usuarios_roles = cursor.fetchall()

    # 📄 Paginación
    paginator = Paginator(usuarios_roles, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Renderizado
    return render(request, "accounts/asignar_rol.html", {
        "form": AsignarRolForm(),
        "page_obj": page_obj,
        "current_page": page_obj.number,
        "total_pages": page_obj.paginator.num_pages,
        "busqueda": busqueda,
    })


# ============================================================
# EDITAR PERFIL (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def editar_perfil_admin(request, rut: int, dv: str):
    dv = (dv or "").upper()

    if request.method == "GET":
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    u.rut, u.digitov, u.nombre, u.apellidop, u.apellidom,
                    u.correo, u.telefono, u.direccion, u.id_comuna,
                    COALESCE(co.nombre, '') AS comuna_nombre,
                    COALESCE(ca.nombre_cargo, '') AS nombre_cargo
                  FROM usuarios u
             LEFT JOIN cuerpo_arbitral c
                    ON c.rut = u.rut AND UPPER(c.digitov) = UPPER(u.digitov)
             LEFT JOIN cargo_arbitral ca ON ca.id_cargo = c.id_cargo
             LEFT JOIN comunas co       ON co.id_comuna = u.id_comuna
                 WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
                 LIMIT 1;
            """, [rut, dv])
            row = cursor.fetchone()

        if not row:
            messages.error(request, "No se encontró el usuario.")
            return redirect("asignar_rol")

        usuario = {
            "rut": f"{row[0]}-{row[1]}",
            "nombre": row[2], "apellidoP": row[3], "apellidoM": row[4],
            "correo": row[5], "telefono": row[6], "direccion": row[7] or "",
            "id_comuna": row[8], "comuna_nombre": row[9] or "",
            "cargo": row[10] or "No asignado",
        }

        with connection.cursor() as cursor:
            cursor.execute("""SELECT id_comuna, nombre FROM comunas ORDER BY LOWER(nombre);""")
            comunas = cursor.fetchall()

        return render(request, "accounts/editar_perfil_admin.html", {
            "usuario": usuario,
            "comunas": comunas,
            "rut_target": rut,
            "dv_target": dv,
        })

    # POST: admin puede editar más campos
    nombre     = (request.POST.get("nombre") or "").strip()
    apellidop  = (request.POST.get("apellidop") or "").strip()
    apellidom  = (request.POST.get("apellidom") or "").strip()
    correo     = (request.POST.get("correo") or "").strip()
    telefono   = (request.POST.get("telefono") or "").strip() or None
    direccion  = (request.POST.get("direccion") or "").strip() or None
    id_comuna  = (request.POST.get("id_comuna") or "").strip()

    # Validaciones mínimas
    if not nombre or not apellidop:
        messages.error(request, "Nombre y Apellido Paterno son obligatorios.")
        return redirect("editar_perfil_admin", rut=rut, dv=dv)

    id_comuna = int(id_comuna) if id_comuna.isdigit() else None

    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE usuarios
               SET nombre = %s,
                   apellidop = %s,
                   apellidom = %s,
                   correo = %s,
                   telefono = %s,
                   direccion = %s,
                   id_comuna = %s
             WHERE rut = %s AND UPPER(digitov) = UPPER(%s);
        """, [nombre, apellidop, apellidom, correo, telefono, direccion, id_comuna, rut, dv])

    messages.success(request, f"Perfil de {rut}-{dv} actualizado correctamente.")
    return redirect("asignar_rol")


# ============================================================
# EDITAR CARGO ARBITRAL (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def editar_cargo_arbitral(request):
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                u.rut, 
                u.digitov,
                u.nombre, 
                u.apellidop, 
                COALESCE(ca.nombre_cargo, 'Sin cargo asignado') AS cargo
            FROM usuarios u
            JOIN usuarios_roles ur 
              ON ur.rut = u.rut AND ur.digitov = u.digitov
            JOIN roles r 
              ON ur.rol_id = r.rol_id
       LEFT JOIN cuerpo_arbitral c 
              ON c.rut = u.rut AND c.digitov = u.digitov
       LEFT JOIN cargo_arbitral ca 
              ON ca.id_cargo = c.id_cargo
           WHERE LOWER(r.nombre_rol) = 'arbitro'
        ORDER BY u.nombre;
        """)
        arbitros = cursor.fetchall()

        cursor.execute("""
            SELECT id_cargo, nombre_cargo 
              FROM cargo_arbitral 
          ORDER BY id_cargo;
        """)
        cargos = cursor.fetchall()

    if request.method == "POST":
        rut_completo = request.POST.get("rut")
        id_cargo = request.POST.get("id_cargo")

        if not rut_completo or not id_cargo:
            messages.error(request, "Debes seleccionar un árbitro y un cargo.")
            return redirect("editar_cargo_arbitral")

        try:
            rut_solo, dv = rut_completo.split("-", 1)
            rut_solo = str(int(rut_solo))
            dv = dv.strip().upper()
        except Exception:
            messages.error(request, "RUT inválido.")
            return redirect("editar_cargo_arbitral")

        with connection.cursor() as cursor:
            cursor.execute("""
                DELETE FROM cuerpo_arbitral 
                 WHERE rut = %s AND digitov = %s;
            """, [rut_solo, dv])
            cursor.execute("""
                INSERT INTO cuerpo_arbitral (
                    cantidad_partidos, 
                    cantidad_tarjetas, 
                    funcion_arb, 
                    cursos, 
                    id_partido, 
                    id_cargo, 
                    rut,
                    digitov
                )
                VALUES (0, 0, '', '', NULL, %s, %s, %s);
            """, [id_cargo, rut_solo, dv])

        messages.success(request, "✅ Cargo arbitral actualizado correctamente.")
        return redirect("editar_cargo_arbitral")

    return render(request, "accounts/editar_cargo_arbitral.html", {
        "arbitros": arbitros,
        "cargos": cargos,
    })


# ============================================================
# ASIGNAR PARTIDOS (solo admin)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Administrador")
def asignar_partidos(request):
    if request.method == "POST":
        partido_id = request.POST.get("id_partido")
        desasignar = request.POST.get("unassign")
        rut_str = (request.POST.get("rut_arbitro") or "").strip()
        dv = (request.POST.get("dv_arbitro") or "").strip().upper()

        # Validaciones básicas
        if not partido_id or not partido_id.isdigit():
            messages.error(request, "ID de partido inválido.")
            return redirect("asignar_partidos")
        partido_id = int(partido_id)

        if desasignar:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE partidos SET rut = NULL, digitov = NULL WHERE id_partido = %s;", [partido_id])
                messages.success(request, f"Asignación eliminada del partido {partido_id}.")
            except Exception as e:
                messages.error(request, f"Error al desasignar: {e}")
            return redirect("asignar_partidos")

        if not (rut_str.isdigit() and len(dv) == 1 and (dv.isdigit() or dv == "K")):
            messages.error(request, "Datos inválidos. Verifica RUT (solo números) y DV (0-9 o K).")
            return redirect("asignar_partidos")

        rut = int(rut_str)

        # Obtener datos del partido actual
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT fecha, hora, club_local, club_visitante
                FROM partidos
                WHERE id_partido = %s;
            """, [partido_id])
            partido = cursor.fetchone()

        if not partido:
            messages.error(request, "Partido no encontrado.")
            return redirect("asignar_partidos")

        fecha, hora, club_local, club_visitante = partido

        # Verificar existencia del árbitro
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT u.nombre, u.apellidop, u.apellidom
                FROM usuarios u
                WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s);
            """, [rut, dv])
            user = cursor.fetchone()

        if not user:
            messages.error(request, f"El usuario {rut}-{dv} no existe.")
            return redirect("asignar_partidos")

        # Verificar que sea árbitro
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 1
                FROM usuarios_roles ur
                JOIN roles r ON r.rol_id = ur.rol_id
                WHERE ur.rut = %s AND UPPER(ur.digitov) = UPPER(%s)
                  AND LOWER(r.nombre_rol) = 'arbitro';
            """, [rut, dv])
            es_arbitro = cursor.fetchone()

        if not es_arbitro:
            messages.error(request, "El usuario indicado no posee rol de Árbitro.")
            return redirect("asignar_partidos")

        # 🔍 Validar conflicto de horario (traslape)
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id_partido, hora
                FROM partidos
                WHERE rut = %s AND UPPER(digitov) = UPPER(%s)
                  AND fecha = %s
                  AND id_partido <> %s;
            """, [rut, dv, fecha, partido_id])
            conflictos = cursor.fetchall()

        if conflictos:
            for c_id, c_hora in conflictos:
                if c_hora == hora:
                    messages.error(request, f"Conflicto: el árbitro ya tiene un partido en el mismo horario.")
                    return redirect("asignar_partidos")

        # 🔧 Actualizar asignación
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE partidos
                    SET rut = %s, digitov = UPPER(%s)
                    WHERE id_partido = %s;
                """, [rut, dv, partido_id])
            nombre_completo = " ".join(filter(None, user))
            messages.success(
                request,
                f"Partido {partido_id} ({fecha} {hora} {club_local} vs {club_visitante}) "
                f"asignado correctamente a {nombre_completo} ({rut}-{dv})."
            )
        except Exception as e:
            messages.error(request, f"Error al asignar: {e}")

        return redirect("asignar_partidos")

    # GET: mostrar últimos 30 días
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT p.id_partido, p.fecha, p.hora, p.club_local, p.club_visitante,
                   p.rut, p.digitov
            FROM partidos p
            WHERE p.fecha >= CURRENT_DATE - INTERVAL '30 day'
            ORDER BY (p.rut IS NULL OR TRIM(COALESCE(p.digitov,'')) = '') DESC,
                     p.fecha ASC, p.hora ASC, p.id_partido ASC;
        """)
        partidos = cursor.fetchall()

    return render(request, "accounts/asignar_partidos.html", {"partidos": partidos})


# ============================================================
# PERFIL ÁRBITRO
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def perfil_arbitro(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    try:
        rut, dv = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Inicie sesión nuevamente.")
        return redirect("login")

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                u.rut,
                u.digitov,
                u.nombre,
                u.apellidop,
                u.apellidom,
                u.correo,
                u.telefono,
                u.direccion,
                u.id_comuna,
                COALESCE(co.nombre, '') AS comuna_nombre,
                COALESCE(ca.nombre_cargo, '') AS nombre_cargo
            FROM usuarios u
       LEFT JOIN cuerpo_arbitral c
              ON c.rut = u.rut AND UPPER(c.digitov) = UPPER(u.digitov)
       LEFT JOIN cargo_arbitral ca
              ON ca.id_cargo = c.id_cargo
       LEFT JOIN comunas co
              ON co.id_comuna = u.id_comuna
           WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
           LIMIT 1;
        """, [rut, dv])
        row = cursor.fetchone()

    if not row:
        messages.error(request, "No se encontró información del árbitro.")
        return redirect("login")

    usuario = {
        "rut": f"{row[0]}-{row[1]}",
        "nombre": row[2],
        "apellidoP": row[3],
        "apellidoM": row[4],
        "correo": row[5],
        "telefono": row[6],
        "direccion": row[7] or "",
        "id_comuna": row[8],
        "comuna_nombre": row[9] or "",
        "cargo": row[10] or "No asignado",
    }

    return render(request, "accounts/perfil_arbitro.html", {"usuario": usuario})


# ============================================================
# EDITAR PERFIL
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def editar_perfil(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    try:
        rut, dv = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Inicie sesión nuevamente.")
        return redirect("login")

    if request.method == "GET":
        # Datos del usuario + comunas para el select
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    u.rut, u.digitov, u.nombre, u.apellidop, u.apellidom,
                    u.correo, u.telefono, u.direccion, u.id_comuna,
                    COALESCE(co.nombre, '') AS comuna_nombre,
                    COALESCE(ca.nombre_cargo, '') AS nombre_cargo
                FROM usuarios u
           LEFT JOIN cuerpo_arbitral c
                  ON c.rut = u.rut AND UPPER(c.digitov) = UPPER(u.digitov)
           LEFT JOIN cargo_arbitral ca ON ca.id_cargo = c.id_cargo
           LEFT JOIN comunas co       ON co.id_comuna = u.id_comuna
               WHERE u.rut = %s AND UPPER(u.digitov) = UPPER(%s)
               LIMIT 1;
            """, [rut, dv])
            row = cursor.fetchone()

        if not row:
            messages.error(request, "No se encontró información del árbitro.")
            return redirect("login")

        usuario = {
            "rut": f"{row[0]}-{row[1]}",
            "nombre": row[2], "apellidoP": row[3], "apellidoM": row[4],
            "correo": row[5], "telefono": row[6], "direccion": row[7] or "",
            "id_comuna": row[8], "comuna_nombre": row[9] or "",
            "cargo": row[10] or "No asignado",
        }

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id_comuna, nombre
                  FROM comunas
              ORDER BY LOWER(nombre);
            """)
            comunas = cursor.fetchall()

        return render(request, "accounts/editar_perfil.html", {
            "usuario": usuario,
            "comunas": comunas,
        })

    # POST: actualizar campos editables
    correo    = (request.POST.get("correo") or "").strip()
    telefono  = (request.POST.get("telefono") or "").strip()
    direccion = (request.POST.get("direccion") or "").strip()
    id_comuna = (request.POST.get("id_comuna") or "").strip()

    if not correo:
        messages.error(request, "El correo es obligatorio.")
        return redirect("editar_perfil")

    correo_lower = correo.lower()
    if not correo_lower.endswith("@gmail.com"):
        messages.error(request, "El correo debe ser una cuenta de Gmail (termina en @gmail.com).")
        return redirect("editar_perfil")

    telefono  = telefono or None
    direccion = direccion or None
    id_comuna = int(id_comuna) if id_comuna.isdigit() else None

    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE usuarios
               SET correo = %s,
                   telefono = %s,
                   direccion = %s,
                   id_comuna = %s
             WHERE rut = %s AND UPPER(digitov) = UPPER(%s);
        """, [correo, telefono, direccion, id_comuna, rut, dv])

    messages.success(request, "Perfil actualizado correctamente.")
    return redirect("perfil_arbitro")


# ============================================================
# PARTIDOS ASIGNADOS (árbitro autenticado)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def partidos_asignados(request):
    """Lista de partidos asignados al árbitro autenticado sin duplicados."""
    if not request.session.get("user_rut"):
        return redirect("login")

    try:
        rut, dv = _parse_rut_from_session(request)
    except Exception:
        messages.error(request, "Sesión inválida. Inicia sesión nuevamente.")
        return redirect("login")

    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT DISTINCT ON (p.id_partido)
                p.id_partido,
                p.fecha,
                p.hora,
                COALESCE(p.club_local, '')     AS local,
                COALESCE(p.club_visitante, '') AS visita,
                COALESCE(ca.nombre, '')        AS cancha,
                COALESCE(p.estado, '')         AS estado,
                (a.id_acta IS NOT NULL)        AS tiene_acta
            FROM partidos p
            LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
            LEFT JOIN acta_partido a ON a.id_partido = p.id_partido
            WHERE p.rut = %s AND UPPER(p.digitov) = UPPER(%s)
            ORDER BY p.id_partido, a.id_acta DESC;
        """, [rut, dv])
        rows = cursor.fetchall()

    partidos = []
    for r in rows:
        id_partido, fch, hora, local, visita, cancha, estado, tiene_acta = r
        partidos.append({
            "id": id_partido,
            "fecha": fch,
            "hora": (hora.strftime("%H:%M") if hora else ""),
            "local": local,
            "visita": visita,
            "cancha": cancha,
            "estado": (estado or "").strip(),
            "tiene_acta": bool(tiene_acta),
        })

    print("🧩 DEBUG PARTIDOS:", partidos)  # Verifica que ya no hay duplicados

    return render(request, "accounts/partidos_asignados.html", {"partidos": partidos})


# ============================================================
# CALENDARIO ÁRBITRO (disponibilidad + partidos)
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def calendario_arbitro(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    rut_full = request.session["user_rut"]
    try:
        rut, dv = rut_full.split("-")
    except ValueError:
        messages.error(request, "Sesión inválida. Vuelve a iniciar sesión.")
        return redirect("login")
    dv = dv.upper()

    # --- Helpers ---
    def valid_hhmm(s: str) -> bool:
        return bool(re.fullmatch(r"^[0-2]\d:[0-5]\d$", s))

    def overlap_exists(cur, dia, ini, fin):
        """
        Chequea traslape con disponibilidad ACTIVA del mismo día.
        Fuerza comparación de TIME para evitar comparar strings.
        """
        cur.execute("""
            SELECT 1
              FROM disponibilidad_arbitro
             WHERE rut = %s
               AND UPPER(digitov) = UPPER(%s)
               AND dia_semana = %s
               AND activo = TRUE
               AND CAST(%s AS TIME) < franja_fin
               AND CAST(%s AS TIME) > franja_inicio
             LIMIT 1;
        """, [rut, dv, dia, ini, fin])
        return cur.fetchone() is not None

    # --- POST (agregar/eliminar disponibilidad) ---
    if request.method == "POST":
        accion = (request.POST.get("accion") or "").strip().lower()

        if accion == "agregar":
            dia_raw = request.POST.get("dia_semana")
            ini = (request.POST.get("franja_inicio") or "").strip()
            fin = (request.POST.get("franja_fin") or "").strip()

            try:
                dia = int(dia_raw)
            except (TypeError, ValueError):
                dia = -1

            if dia not in range(0, 7):
                messages.error(request, "Selecciona un día válido (0=Dom … 6=Sáb).")
                return redirect("calendario_arbitro")

            if not (ini and fin and valid_hhmm(ini) and valid_hhmm(fin)):
                messages.error(request, "Formato de hora inválido. Usa HH:MM (ej. 09:00).")
                return redirect("calendario_arbitro")

            if ini >= fin:
                messages.error(request, "La hora de inicio debe ser menor que la de término.")
                return redirect("calendario_arbitro")

            try:
                with connection.cursor() as cursor:
                    if overlap_exists(cursor, dia, ini, fin):
                        messages.error(request, "Ya tienes disponibilidad que se solapa en ese día/horario.")
                        return redirect("calendario_arbitro")

                    cursor.execute("""
                        INSERT INTO disponibilidad_arbitro
                            (rut, digitov, dia_semana, franja_inicio, franja_fin, activo)
                        VALUES (%s, UPPER(%s), %s, CAST(%s AS TIME), CAST(%s AS TIME), TRUE);
                    """, [rut, dv, dia, ini, fin])

                messages.success(request, "Disponibilidad agregada.")
            except Exception as e:
                messages.error(request, f"Error al guardar disponibilidad: {e}")
            return redirect("calendario_arbitro")

        elif accion == "eliminar":
            disp_id = request.POST.get("disp_id")
            if not disp_id:
                messages.error(request, "No se indicó el registro a eliminar.")
                return redirect("calendario_arbitro")

            try:
                with connection.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM disponibilidad_arbitro
                         WHERE id = %s
                           AND rut = %s
                           AND UPPER(digitov) = UPPER(%s);
                    """, [disp_id, rut, dv])

                if cursor.rowcount:
                    messages.success(request, "Disponibilidad eliminada.")
                else:
                    messages.warning(request, "No se encontró el registro o no te pertenece.")
            except Exception as e:
                messages.error(request, f"Error al eliminar: {e}")
            return redirect("calendario_arbitro")

        else:
            messages.warning(request, "Acción no reconocida.")
            return redirect("calendario_arbitro")

    # --- GET: cargar partidos y disponibilidad ---
    try:
        with connection.cursor() as cursor:
            # ORDER BY compatible con MySQL (NULLS al final sin 'NULLS LAST')
            cursor.execute("""
                SELECT p.id_partido, p.fecha, p.hora, p.club_local, p.club_visitante,
                       COALESCE(can.nombre, 'No definida') AS cancha
                  FROM partidos p
             LEFT JOIN cancha can ON can.id_cancha = p.id_cancha
                 WHERE p.rut = %s
                   AND UPPER(p.digitov) = UPPER(%s)
              ORDER BY p.fecha ASC, (p.hora IS NULL) ASC, p.hora ASC, p.id_partido ASC;
            """, [rut, dv])
            mis_partidos = cursor.fetchall()

            cursor.execute("""
                SELECT id, dia_semana, franja_inicio, franja_fin, activo
                  FROM disponibilidad_arbitro
                 WHERE rut = %s
                   AND UPPER(digitov) = UPPER(%s)
              ORDER BY dia_semana ASC, franja_inicio ASC;
            """, [rut, dv])
            disp_raw = cursor.fetchall()
    except Exception as e:
        messages.error(request, f"Error al cargar datos: {e}")
        mis_partidos, disp_raw = [], []

    # Mapeo 0..6 -> nombres de día
    dias_nombres = ["Domingo","Lunes","Martes","Miércoles","Jueves","Viernes","Sábado"]

    # Normaliza la disponibilidad a dicts y formatea hora como HH:MM
    disponibilidad = []
    for _id, dia_idx, ini, fin, activo in disp_raw:
        ini_txt = ini.strftime("%H:%M") if hasattr(ini, "strftime") else str(ini)[:5]
        fin_txt = fin.strftime("%H:%M") if hasattr(fin, "strftime") else str(fin)[:5]
        disponibilidad.append({
            "id": _id,
            "dia_idx": dia_idx,
            "dia_nombre": dias_nombres[dia_idx] if 0 <= dia_idx <= 6 else "—",
            "inicio": ini_txt,
            "fin": fin_txt,
            "activo": bool(activo),
        })

    return render(request, "accounts/calendario_arbitro.html", {
        "partidos": mis_partidos,             # lista de tuplas
        "disponibilidad": disponibilidad,     # lista de dicts
        "dias_select": list(enumerate(dias_nombres)),  # [(0,"Domingo"),...,(6,"Sábado")]
    })


# ============================================================
# PANEL TURNO
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def panel_turno(request):
    if not request.session.get("user_rut"):
        return redirect("login")
    return render(request, "accounts/panel_turno.html")


# ============================================================
# TRIBUNAL DE DISCIPLINA
# ============================================================
@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@role_required("Tribunal de Disciplina")
def panel_tribunal(request):
    """Panel principal del Tribunal de Disciplina."""
    if not request.session.get("user_rut"):
        return redirect("login")

    user_nombre = request.session.get("user_nombre", "Usuario")

    # ============================================================
    # 🔹 Si el tribunal actualiza una acta
    # ============================================================
    if request.method == "POST":
        id_acta = request.POST.get("id_acta")
        nuevo_estado = request.POST.get("estado")
        observacion = request.POST.get("observacion", "").strip()

        if id_acta and nuevo_estado:
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE estado_acta
                    SET nombre_estado = %s,
                        descripcion = %s
                    WHERE id_acta = %s;
                """, [
                    nuevo_estado,
                    observacion or f"Estado actualizado a '{nuevo_estado}' por el Tribunal de Disciplina.",
                    id_acta
                ])
            # ✅ Mensaje visible solo dentro del panel
            request.session["mensaje_acta"] = f"✅ Acta #{id_acta} actualizada a '{nuevo_estado}'."
            return redirect("panel_tribunal")

    # ============================================================
    # 🔹 Mensaje de bienvenida (solo visible en panel)
    # ============================================================
    mensaje_bienvenida = None
    if not request.session.get("bienvenida_mostrada", False):
        mensaje_bienvenida = f"Bienvenido {user_nombre}"
        request.session["bienvenida_mostrada"] = True  # Se mostrará solo una vez

    # 🔹 Mostrar mensajes del panel (no en login)
    mensaje = request.session.pop("mensaje_acta", None)

    # ============================================================
    # 🔹 Consultas separadas
    # ============================================================
    with connection.cursor() as cursor:
        # Actas pendientes o en revisión
        cursor.execute("""
            SELECT 
                a.id_acta, p.club_local, p.club_visitante, p.fecha,
                COALESCE(a.incidentes, 'Sin incidentes reportados'),
                COALESCE(ea.nombre_estado, 'Pendiente')
            FROM acta_partido a
            JOIN partidos p ON a.id_partido = p.id_partido
            JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE ea.nombre_estado IN ('Pendiente', 'En revisión')
            ORDER BY p.fecha DESC;
        """)
        actas_recibidas = cursor.fetchall()

        # Actas revisadas
        cursor.execute("""
            SELECT 
                a.id_acta, p.club_local, p.club_visitante, p.fecha,
                COALESCE(a.incidentes, 'Sin incidentes reportados'),
                COALESCE(ea.nombre_estado, 'Pendiente')
            FROM acta_partido a
            JOIN partidos p ON a.id_partido = p.id_partido
            JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE ea.nombre_estado IN ('Aprobada', 'Rechazada')
            ORDER BY p.fecha DESC;
        """)
        actas_revisadas = cursor.fetchall()

    # ============================================================
    # 🔹 Contexto
    # ============================================================
    contexto = {
        "user_nombre": user_nombre,
        "actas_recibidas": actas_recibidas,
        "actas_revisadas": actas_revisadas,
        "mensaje": mensaje,                    # Actas actualizadas
        "mensaje_bienvenida": mensaje_bienvenida,  # Solo visible en el panel
    }

    return render(request, "accounts/tribunal.html", contexto)





# ============================================================
# SECRETARÍA
# ============================================================

@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def panel_secretaria(request):
    if not request.session.get("user_rut"):
        return redirect("login")

    rol = request.session.get("user_rol", "")
    if _normalize_role(rol) not in ("secretario", "secretaria"):
        messages.error(request, "No tienes permisos para acceder a esta página.")
        return redirect("login")

    user_nombre = request.session.get("user_nombre", "Usuario")
    return render(request, "accounts/secretaria.html", {
        "user_nombre": user_nombre,
    })

# ============================================================
# HISTORIAL Y DETALLE DE ACTAS DEL ÁRBITRO
# ============================================================
@role_required("Arbitro")
def actas_arbitro(request):
    rut, dv = _parse_rut_from_session(request)
    id_ver = request.GET.get("ver")  # parámetro ?ver=<id_acta>

    with connection.cursor() as cursor:
        # Si se solicita ver una acta específica
        if id_ver:
            cursor.execute("""
                SELECT 
                    a.id_acta,
                    p.club_local,
                    p.club_visitante,
                    p.fecha,
                    p.hora,
                    COALESCE(ca.nombre, 'Cancha sin asignar') AS cancha,
                    a.goles_local,
                    a.goles_visita,
                    a.incidentes,
                    COALESCE(ea.nombre_estado, 'Pendiente') AS estado,
                    COALESCE(ea.descripcion, '') AS descripcion
                FROM acta_partido a
                JOIN partidos p ON p.id_partido = a.id_partido
                LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
                LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
                WHERE a.id_acta = %s
                LIMIT 1;
            """, [id_ver])
            acta = cursor.fetchone()

            # 🔸 Si no se encuentra el acta, mensaje más coherente
            if not acta:
                messages.warning(request, "El acta no está disponible o fue eliminada.")
                return redirect("actas_arbitro")

            # 🔹 Renderizar el detalle del acta
            return render(request, "accounts/ver_acta.html", {"acta": acta})

        # Si no se pasa el parámetro ?ver, mostrar el listado completo
        cursor.execute("""
            SELECT 
                a.id_acta,
                p.club_local,
                p.club_visitante,
                p.fecha,
                a.goles_local,
                a.goles_visita,
                COALESCE(a.incidentes, 'Sin incidentes') AS incidentes,
                COALESCE(ea.nombre_estado, 'Pendiente') AS estado
            FROM acta_partido a
            JOIN partidos p ON a.id_partido = p.id_partido
            LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE a.rut = %s AND UPPER(a.digitov) = UPPER(%s)
            ORDER BY p.fecha DESC;
        """, [rut, dv])
        actas = cursor.fetchall()

    return render(request, "accounts/actas_arbitro.html", {"actas": actas})


# ============================================================
# Redacción de Actas - Panel Árbitro
# ============================================================
@role_required("Arbitro")
def redactar_acta(request, id_partido):
    """
    Permite al árbitro redactar el acta de un partido finalizado.
    Evita duplicados y solo permite editar si el tribunal devolvió la acta.
    """
    rut, dv = _parse_rut_from_session(request)

    # 🔹 Obtener datos del partido asignado
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT 
                p.id_partido,
                p.club_local,
                p.club_visitante,
                p.fecha,
                p.hora,
                COALESCE(ca.nombre, 'Cancha sin asignar') AS cancha,
                p.estado
            FROM partidos p
            LEFT JOIN cancha ca ON ca.id_cancha = p.id_cancha
            WHERE p.id_partido = %s AND p.rut = %s AND UPPER(p.digitov) = UPPER(%s)
            LIMIT 1;
        """, [id_partido, rut, dv])
        partido = cursor.fetchone()

    # 🔸 Validaciones básicas
    if not partido:
        messages.error(request, "❌ No tienes permiso para este partido o no existe.")
        return redirect("partidos_asignados")

    if partido[6] != "Finalizado":
        messages.warning(request, "⚠️ Solo puedes redactar actas de partidos finalizados.")
        return redirect("partidos_asignados")

    # 🔹 Verificar si ya existe un acta para este partido
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT a.id_acta, COALESCE(ea.nombre_estado, 'Pendiente') AS estado
            FROM acta_partido a
            LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
            WHERE a.id_partido = %s
            ORDER BY a.id_acta DESC
            LIMIT 1;
        """, [id_partido])
        acta_existente = cursor.fetchone()

    # Si existe una acta, controlar qué hacer
    if acta_existente:
        id_acta_existente, estado_actual = acta_existente

        # Si el acta está en revisión o aprobada → no permitir redacción nueva
        if estado_actual in ["Pendiente", "En revisión", "Aprobada"]:
            messages.warning(request, f"⚠️ Ya existe un acta en estado '{estado_actual}'. No puedes crear otra.")
            return redirect("actas_arbitro")

        # Si el tribunal pidió corrección → permitir edición del acta existente
        if estado_actual == "Revisión solicitada":
            messages.info(request, "✏️ El tribunal devolvió esta acta para corrección. Puedes editarla nuevamente.")
            # Aquí podrías cargar el acta existente y permitir su edición (futuro upgrade)

    # 🔹 Procesar formulario (POST)
    if request.method == "POST":
        goles_local = request.POST.get("goles_local")
        goles_visita = request.POST.get("goles_visita")
        incidentes = request.POST.get("incidentes", "").strip()
        tarjetas_amarillas = request.POST.get("tarjetas_amarillas") or None
        tarjetas_rojas = request.POST.get("tarjetas_rojas") or None

        # Validación básica
        if goles_local == "" or goles_visita == "":
            messages.warning(request, "⚠️ Debes ingresar los goles de ambos equipos.")
            return redirect(request.path)

        with connection.cursor() as cursor:
            # 🔸 Insertar el acta del partido (solo si no existe una válida)
            cursor.execute("""
                INSERT INTO acta_partido (
                    id_partido, rut, digitov,
                    fecha_encuentro,
                    goles_local, goles_visita,
                    incidentes, tarjetas_amarillas, tarjetas_rojas
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id_acta;
            """, [
                partido[0], rut, dv,
                partido[3],
                goles_local, goles_visita,
                incidentes, tarjetas_amarillas, tarjetas_rojas
            ])
            id_acta = cursor.fetchone()[0]

            # 🔸 Crear el estado inicial (“Pendiente”)
            cursor.execute("""
                INSERT INTO estado_acta (id_acta, nombre_estado, descripcion)
                VALUES (%s, %s, %s);
            """, [
                id_acta,
                "Pendiente",
                "Acta enviada por el árbitro, pendiente de revisión por el tribunal."
            ])

        messages.success(request, "✅ El acta se ha enviado al Tribunal de Disciplina para revisión.")
        return redirect("actas_arbitro")

    # 🔹 Mostrar formulario de redacción
    contexto = {
        "partido": {
            "id": partido[0],
            "local": partido[1],
            "visita": partido[2],
            "fecha": partido[3],
            "hora": partido[4],
            "cancha": partido[5],
            "estado": partido[6],
        }
    }

    return render(request, "accounts/redactar_actas.html", contexto)

# ============================================================
# DESCARGAR ACTA EN PDF
# ============================================================
from django.http import FileResponse, Http404
from django.contrib import messages
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
import io

@role_required("Tribunal de Disciplina")
def descargar_acta_pdf(request, id_acta):
    """
    Genera y descarga el acta en formato PDF con sus datos principales.
    """
    try:
        # --- Obtener los datos del acta ---
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    a.id_acta,
                    p.club_local,
                    p.club_visitante,
                    p.fecha,
                    a.incidentes,
                    COALESCE(ea.nombre_estado, 'Pendiente')
                FROM acta_partido a
                JOIN partidos p ON a.id_partido = p.id_partido
                LEFT JOIN estado_acta ea ON ea.id_acta = a.id_acta
                WHERE a.id_acta = %s
                LIMIT 1;
            """, [id_acta])
            acta = cursor.fetchone()

        if not acta:
            messages.error(request, "No se encontró el acta solicitada.")
            raise Http404("Acta no encontrada.")

        # --- Datos principales ---
        id_acta, local, visita, fecha, incidentes, estado = acta
        nombre_archivo = request.GET.get("nombre", f"Acta_{id_acta}.pdf")

        # --- Crear el PDF en memoria ---
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        pdf.setTitle("Acta de Partido")

        # Márgenes
        ancho, alto = A4
        margen_x, margen_y = 2 * cm, 2 * cm
        y = alto - margen_y

        # --- Encabezado ---
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawCentredString(ancho / 2, y, "ACTA DE PARTIDO")
        y -= 30

        pdf.setFont("Helvetica", 12)
        pdf.drawString(margen_x, y, f"Fecha del partido: {fecha.strftime('%d/%m/%Y')}")
        y -= 20
        pdf.drawString(margen_x, y, f"Encuentro: {local} vs {visita}")
        y -= 20
        pdf.drawString(margen_x, y, f"Estado actual del acta: {estado}")
        y -= 40

        # --- Detalle de incidentes ---
        pdf.setFont("Helvetica-Bold", 13)
        pdf.drawString(margen_x, y, "Incidentes / Observaciones:")
        y -= 20

        pdf.setFont("Helvetica", 11)
        texto = acta[4] or "Sin incidentes registrados."
        text_obj = pdf.beginText(margen_x, y)
        text_obj.setLeading(15)
        text_obj.textLines(texto)
        pdf.drawText(text_obj)
        y -= (len(texto.split("\n")) * 15) + 30

        # --- Pie de página ---
        pdf.setFont("Helvetica-Oblique", 10)
        pdf.drawString(margen_x, 60, "Sistema ANFA - Tribunal de Disciplina")
        pdf.drawRightString(ancho - margen_x, 60, f"Acta Nº {id_acta}")

        pdf.showPage()
        pdf.save()

        # --- Retornar el archivo ---
        buffer.seek(0)
        return FileResponse(buffer, as_attachment=True, filename=nombre_archivo)

    except Exception as e:
        print("Error al generar PDF:", e)
        messages.error(request, "Ocurrió un error al generar el PDF del acta.")
        raise Http404("Error generando PDF del acta.")
