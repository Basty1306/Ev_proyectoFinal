from django.shortcuts import redirect
from django.contrib import messages
from functools import wraps

def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if "user_rut" not in request.session:
                messages.warning(request, "Debes iniciar sesión primero.")
                return redirect("login")

            rol = request.session.get("user_rol")

            # ✅ Si el rol tiene permiso, continúa
            if rol in allowed_roles:
                return view_func(request, *args, **kwargs)

            # 🚫 Si no tiene permiso, lo mandamos según rol
            if rol == "Arbitro":
                return redirect("perfil_arbitro")

            messages.error(request, "Acceso denegado: no tienes permisos.")
            return redirect("login")

        return wrapper
    return decorator

