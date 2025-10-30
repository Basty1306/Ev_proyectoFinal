from django.contrib import admin
from django.urls import path
from accounts import views as v
from accounts.utils import role_required

urlpatterns = [
    # === PÚBLICAS ===
    path("login/", v.login_view, name="login"),
    path("logout/", v.logout_view, name="logout"),
    # Renombrada para evitar colisión con la de árbitro
    path("perfil/editar/", v.editar_perfil, name="editar_perfil_self"),

    # === ADMIN ===
    path("", role_required("Administrador")(v.dashboard), name="dashboard"),
    path("usuarios/registrar/", role_required("Administrador")(v.registrar_usuario), name="registrar_usuario"),
    path("roles/asignar/", role_required("Administrador")(v.asignar_rol), name="asignar_rol"),
    path("arbitros/editar-cargo/", role_required("Administrador")(v.editar_cargo_arbitral), name="editar_cargo_arbitral"),
    path("usuarios/<int:rut>-<str:dv>/editar/", role_required("Administrador")(v.editar_perfil_admin), name="editar_perfil_admin"),
    # ✅ FALTABA ESTA RUTA
    path("partidos/asignar/", role_required("Administrador")(v.asignar_partidos), name="asignar_partidos"),

    # === ÁRBITRO ===
    path("arbitros/perfil/", v.perfil_arbitro, name="perfil_arbitro"),
    path("arbitros/perfil/editar/", v.editar_perfil, name="editar_perfil"),
    path("arbitros/partidos/", v.partidos_asignados, name="partidos_asignados"),
    path("arbitros/calendario/", v.calendario_arbitro, name="calendario_arbitro"),
    path("arbitros/actas/", v.actas_arbitro, name="actas_arbitro"),
    path("arbitro/actas/redactar/<int:id_partido>/", v.redactar_acta, name="redactar_acta"),
    path("tribunal/acta/<int:id_acta>/descargar/", v.descargar_acta_pdf, name="descargar_acta"),





    # === ROL DEL TURNO ===
    path("turno/", v.panel_turno, name="panel_turno"),

    # === TRIBUNAL ===
    path("tribunal/", role_required("Tribunal de Disciplina")(v.panel_tribunal), name="panel_tribunal"),

    # === SECRETARÍA ===
    path("secretaria/", v.panel_secretaria, name="panel_secretaria"),

    # === ADMIN DJANGO ===
    path("admin/", admin.site.urls),
]



