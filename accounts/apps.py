from django.apps import AppConfig
import logging

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

    def ready(self):
        """
        Al iniciar el servidor, elimina TODAS las sesiones guardadas.
        Funciona si usas el motor por defecto: django.contrib.sessions (DB-backed).
        Si usas cache/cached_db, abajo también limpiamos el caché.
        """
        logger = logging.getLogger(__name__)

        # 1) Intentar borrar sesiones si usas motor de sesiones en DB
        try:
            from django.contrib.sessions.models import Session
            deleted, _ = Session.objects.all().delete()
            logger.info("Sessions purged on boot: %s", deleted)
        except Exception as e:
            logger.warning("Could not purge DB sessions on boot: %s", e)

        # 2) Si usas 'cache' o 'cached_db', limpia el caché también (no hace daño si no lo usas)
        try:
            from django.core.cache import cache
            cache.clear()
            logger.info("Cache cleared on boot.")
        except Exception as e:
            logger.warning("Could not clear cache on boot: %s", e)
