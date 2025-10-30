from django.contrib.auth.backends import BaseBackend
from django.db import connection
from .models import UserLike

class RutBackend(BaseBackend):
    """
    Backend de autenticación personalizado para ANFA.
    Valida usuarios usando las tablas:
      - login (usuario, contrasena, estado, rut)
      - usuarios (rut, digitov, nombre, apellidom)
      - usuarios_roles + roles (para roles asociados)
    """

    def authenticate(self, request, username=None, password=None):
        """
        username = RUT numérico (sin dígito verificador)
        password = contraseña ingresada
        """
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT l.rut, l.contrasena, l.estado, u.nombre, u.apellidom, u.digitov
                FROM login l
                JOIN usuarios u ON l.rut = u.rut
                WHERE l.rut = %s
            """, [username])
            row = cursor.fetchone()

        # Si no se encuentra el usuario
        if not row:
            return None

        rut, contrasena_db, estado, nombre, apellidom, digitov = row

        # Validar contraseña y estado
        if contrasena_db != password or estado.lower() != "activo":
            return None

        # Obtener los roles asociados
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT r.nombre_rol
                FROM usuarios_roles ur
                JOIN roles r ON ur.rol_id = r.rol_id
                WHERE ur.rut = %s
            """, [rut])
            roles = [r[0] for r in cursor.fetchall()]

        # Crear instancia temporal (sin guardarla en la BD)
        user = UserLike(rut=f"{rut}-{digitov}", nombre=f"{nombre} {apellidom}")
        user._roles = roles or []

        return user

    def get_user(self, user_id):
        """Django requiere este método aunque no se use con sesiones estándar."""
        return None
