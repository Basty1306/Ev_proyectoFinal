from django.shortcuts import redirect
from django.urls import reverse
from django.core.cache import cache

SAFE_PREFIXES = ("/static/", "/media/")
SAFE_PATHS = ("/login/", "/logout/", "/admin/login/")

class InvalidateOnBootMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path or "/"

        # 1) Nunca interceptar estáticos ni rutas seguras (login/logout/admin login)
        if path.startswith(SAFE_PREFIXES) or any(path.startswith(p) for p in SAFE_PATHS):
            return self.get_response(request)

        # 2) Si no hay marca de arranque en sesión, todavía NO redirijas si el destino es login,
        #    pero como ya lo filtramos arriba, aquí podemos validar directo.
        current_epoch = cache.get("BOOT_EPOCH")
        session_epoch = request.session.get("BOOT_EPOCH")

        # 3) Si la sesión no corresponde a este arranque, invalidar y mandar a login
        if current_epoch is not None and session_epoch != current_epoch:
            request.session.flush()
            return redirect(reverse("login"))

        return self.get_response(request)