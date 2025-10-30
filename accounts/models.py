from django.db import models


# ===========================================================
# 1️⃣ CLASE AUXILIAR (NO CREA TABLA)
# ===========================================================
class UserLike:
    """Clase auxiliar usada para autenticación personalizada"""
    def __init__(self, rut, nombre):
        self.rut = rut
        self.nombre = nombre
        self._roles = []

    def __str__(self):
        return self.nombre


class ActaPartido(models.Model):
    id_acta = models.AutoField(primary_key=True)
    sancion = models.CharField(max_length=100, blank=True, null=True)
    fecha_encuentro = models.DateField(blank=True, null=True)
    incidentes = models.TextField(blank=True, null=True)
    resultado = models.CharField(max_length=20, blank=True, null=True)
    id_partido = models.ForeignKey('Partidos', models.DO_NOTHING, db_column='id_partido')
    id_torneo = models.ForeignKey('Torneo', models.DO_NOTHING, db_column='id_torneo', blank=True, null=True)
    rut = models.ForeignKey('Usuario', models.DO_NOTHING, db_column='rut')
    digitov = models.CharField(max_length=1)

    class Meta:
        managed = False
        db_table = 'acta_partido'


class Anuncio(models.Model):
    id_anuncio = models.AutoField(primary_key=True)
    titulo = models.CharField(max_length=100, blank=True, null=True)
    fecha_publicacion = models.DateTimeField(blank=True, null=True)
    descripcion = models.TextField(blank=True, null=True)
    id_partido = models.ForeignKey('Partidos', models.DO_NOTHING, db_column='id_partido', blank=True, null=True)
    rut = models.ForeignKey('Usuario', models.DO_NOTHING, db_column='rut')
    digitov = models.CharField(max_length=1)

    class Meta:
        managed = False
        db_table = 'anuncio'


class Cancha(models.Model):
    id_cancha = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    direccion = models.CharField(max_length=50, blank=True, null=True)
    estado = models.CharField(max_length=20, blank=True, null=True)
    superficie = models.CharField(max_length=20, blank=True, null=True)
    disponibilidad = models.CharField(max_length=20, blank=True, null=True)
    id_comuna = models.ForeignKey('Comuna', models.DO_NOTHING, db_column='id_comuna')

    class Meta:
        managed = False
        db_table = 'cancha'


class CargoArbitral(models.Model):
    id_cargo = models.AutoField(primary_key=True)
    nombre_cargo = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'cargo_arbitral'


class Club(models.Model):
    id_club = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100)
    descripcion = models.TextField(blank=True, null=True)
    contacto = models.CharField(max_length=100, blank=True, null=True)
    id_cancha = models.ForeignKey(Cancha, models.DO_NOTHING, db_column='id_cancha', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'club'


class ClubSerie(models.Model):
    id_club_serie = models.AutoField(primary_key=True)
    fecha_inicio = models.DateField(blank=True, null=True)
    estado = models.CharField(max_length=30, blank=True, null=True)
    id_club = models.ForeignKey(Club, models.DO_NOTHING, db_column='id_club')
    id_serie = models.ForeignKey('Serie', models.DO_NOTHING, db_column='id_serie')

    class Meta:
        managed = False
        db_table = 'club_serie'


class Comuna(models.Model):
    id_comuna = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=50)
    provincia = models.CharField(max_length=50, blank=True, null=True)
    codigo_postal = models.IntegerField(blank=True, null=True)
    id_region = models.ForeignKey('Region', models.DO_NOTHING, db_column='id_region')

    class Meta:
        managed = False
        db_table = 'comunas'


class CuerpoArbitral(models.Model):
    id_historial = models.AutoField(primary_key=True)
    cantidad_partidos = models.IntegerField(blank=True, null=True)
    cantidad_tarjetas = models.IntegerField(blank=True, null=True)
    funcion_arb = models.CharField(max_length=50, blank=True, null=True)
    cursos = models.TextField(blank=True, null=True)
    id_partido = models.ForeignKey('Partidos', models.DO_NOTHING, db_column='id_partido', blank=True, null=True)
    id_cargo = models.ForeignKey(CargoArbitral, models.DO_NOTHING, db_column='id_cargo', blank=True, null=True)
    rut = models.ForeignKey('Usuario', models.DO_NOTHING, db_column='rut')
    digitov = models.CharField(max_length=1)

    class Meta:
        managed = False
        db_table = 'cuerpo_arbitral'


class Documento(models.Model):
    id_documento = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100)
    tipo_documento = models.CharField(max_length=50, blank=True, null=True)
    archivo = models.TextField(blank=True, null=True)
    fecha_subida = models.DateField(blank=True, null=True)
    id_club = models.ForeignKey(Club, models.DO_NOTHING, db_column='id_club')

    class Meta:
        managed = False
        db_table = 'documento'


class Estado(models.Model):
    id_estado = models.AutoField(primary_key=True)
    nombre_estado = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'estado'


class EstadoActa(models.Model):
    id_estado_acta = models.AutoField(primary_key=True)
    id_estado = models.ForeignKey(Estado, models.DO_NOTHING, db_column='id_estado', blank=True, null=True)
    id_acta = models.ForeignKey(ActaPartido, models.DO_NOTHING, db_column='id_acta', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'estado_acta'


class JugadorPartido(models.Model):
    pk = models.CompositePrimaryKey('id_jugador', 'id_partido')
    id_jugador = models.ForeignKey('Jugadores', models.DO_NOTHING, db_column='id_jugador')
    id_partido = models.ForeignKey('Partidos', models.DO_NOTHING, db_column='id_partido')

    class Meta:
        managed = False
        db_table = 'jugador_partido'


class Jugadores(models.Model):
    rut_jugador = models.IntegerField(primary_key=True)
    digitov = models.CharField(max_length=1)
    nombre = models.CharField(max_length=30, blank=True, null=True)
    apellido = models.CharField(max_length=30, blank=True, null=True)
    fecha_nacimiento = models.DateField(blank=True, null=True)
    estado = models.CharField(max_length=30, blank=True, null=True)
    num_camiseta = models.IntegerField(blank=True, null=True)
    id_serie = models.ForeignKey('Serie', models.DO_NOTHING, db_column='id_serie', blank=True, null=True)
    id_club = models.ForeignKey('Club', models.DO_NOTHING, db_column='id_club', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'jugadores'


class Ligas(models.Model):
    id_liga = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100, blank=True, null=True)
    temporada = models.CharField(max_length=50, blank=True, null=True)
    estado = models.CharField(max_length=30, blank=True, null=True)
    id_comuna = models.ForeignKey(Comuna, models.DO_NOTHING, db_column='id_comuna', blank=True, null=True)
    id_club = models.ForeignKey(Club, models.DO_NOTHING, db_column='id_club', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'ligas'


class Login(models.Model):
    rut = models.IntegerField(primary_key=False)
    digitov = models.CharField(max_length=1)
    contrasena = models.CharField(max_length=100)
    estado = models.CharField(max_length=20, blank=True, null=True)
    fecha_logueo = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'login'
        unique_together = (('rut', 'digitov'),)


class Pagos(models.Model):
    id_pago = models.AutoField(primary_key=True)
    monto = models.IntegerField()
    estado = models.CharField(max_length=20, blank=True, null=True)
    fecha_pago = models.DateField(blank=True, null=True)
    id_tipo = models.ForeignKey('TipoPago', models.DO_NOTHING, db_column='id_tipo', blank=True, null=True)
    rut = models.ForeignKey('Usuario', models.DO_NOTHING, db_column='rut')
    digitov = models.CharField(max_length=1)
    id_partido = models.ForeignKey('Partidos', models.DO_NOTHING, db_column='id_partido')

    class Meta:
        managed = False
        db_table = 'pagos'


class Partidos(models.Model):
    id_partido = models.AutoField(primary_key=True)
    fecha = models.DateField(blank=True, null=True)
    hora = models.TimeField(blank=True, null=True)
    club_local = models.CharField(max_length=50, blank=True, null=True)
    club_visitante = models.CharField(max_length=50, blank=True, null=True)
    resultado = models.CharField(max_length=10, blank=True, null=True)
    estado = models.CharField(max_length=30, blank=True, null=True)
    id_club = models.ForeignKey(Club, models.DO_NOTHING, db_column='id_club', blank=True, null=True)
    id_cancha = models.ForeignKey(Cancha, models.DO_NOTHING, db_column='id_cancha', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'partidos'


class Region(models.Model):
    id_region = models.AutoField(primary_key=True)
    nombre_region = models.CharField(max_length=50)

    class Meta:
        managed = False
        db_table = 'region'


class Reglamento(models.Model):
    id_reglamento = models.AutoField(primary_key=True)
    reglas = models.TextField(blank=True, null=True)
    activo = models.BooleanField(blank=True, null=True)
    fecha_vigencia = models.DateField(blank=True, null=True)
    fecha_termino = models.DateField(blank=True, null=True)
    fecha_creacion = models.DateField(blank=True, null=True)
    rut = models.ForeignKey('Usuario', models.DO_NOTHING, db_column='rut')
    digitov = models.CharField(max_length=1)

    class Meta:
        managed = False
        db_table = 'reglamento'


class Rol(models.Model):
    rol_id = models.AutoField(primary_key=True)
    nombre_rol = models.CharField(unique=True, max_length=100)

    class Meta:
        managed = False
        db_table = 'roles'


class Sanciones(models.Model):
    id_sancion = models.AutoField(primary_key=True)
    tipo = models.CharField(max_length=50, blank=True, null=True)
    fecha_inc = models.DateField(blank=True, null=True)
    motivo = models.TextField(blank=True, null=True)
    id_jugador = models.ForeignKey(Jugadores, models.DO_NOTHING, db_column='id_jugador', blank=True, null=True)
    id_club = models.ForeignKey(Club, models.DO_NOTHING, db_column='id_club', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'sanciones'


class Serie(models.Model):
    id_serie = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100)
    descripcion = models.TextField(blank=True, null=True)
    categoria = models.CharField(max_length=50, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'serie'


class Tablaposiciones(models.Model):
    id_tabla = models.AutoField(primary_key=True)
    pa_jugados = models.IntegerField(blank=True, null=True)
    pa_ganados = models.IntegerField(blank=True, null=True)
    pa_perdidos = models.IntegerField(blank=True, null=True)
    pa_empatados = models.IntegerField(blank=True, null=True)
    goles_favor = models.IntegerField(blank=True, null=True)
    goles_contra = models.IntegerField(blank=True, null=True)
    puntos = models.IntegerField(blank=True, null=True)
    id_torneo = models.ForeignKey('Torneo', models.DO_NOTHING, db_column='id_torneo', blank=True, null=True)
    id_club = models.ForeignKey(Club, models.DO_NOTHING, db_column='id_club', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'tablaposiciones'


class TipoPago(models.Model):
    id_tipo = models.AutoField(primary_key=True)
    nombre_metodo_pago = models.CharField(max_length=100, blank=True, null=True)
    detalle = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'tipo_pago'


class Torneo(models.Model):
    id_torneo = models.AutoField(primary_key=True)
    nombre = models.CharField(max_length=100, blank=True, null=True)
    temporada = models.CharField(max_length=50, blank=True, null=True)
    tipo = models.CharField(max_length=50, blank=True, null=True)
    fec_inicio = models.DateField(blank=True, null=True)
    fec_fin = models.DateField(blank=True, null=True)
    fixture = models.TextField(blank=True, null=True)
    id_liga = models.ForeignKey(Ligas, models.DO_NOTHING, db_column='id_liga', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'torneo'


class Usuario(models.Model):
    rut = models.IntegerField(primary_key=True)
    digitov = models.CharField(max_length=1)
    nombre = models.CharField(max_length=50)
    apellidop = models.CharField(max_length=50)
    apellidom = models.CharField(max_length=50)
    telefono = models.CharField(max_length=20, blank=True, null=True)
    correo = models.CharField(unique=True, max_length=150)
    direccion = models.CharField(max_length=50, blank=True, null=True)
    fecharegistro = models.DateField(blank=True, null=True)
    id_comuna = models.ForeignKey('Comuna', models.DO_NOTHING, db_column='id_comuna', blank=True, null=True)
    id_club = models.ForeignKey('Club', models.DO_NOTHING, db_column='id_club', blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'usuarios'

    @property
    def rut_completo(self):
        return f"{self.rut}-{self.digitov}"


class UsuarioRol(models.Model):
    estado = models.CharField(max_length=50, blank=True, null=True)
    fecha_asignacion = models.DateField(blank=True, null=True)
    rut = models.ForeignKey(Usuario, models.DO_NOTHING, db_column='rut')
    digitov = models.CharField(max_length=1)
    rol = models.ForeignKey(Rol, models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'usuarios_roles'
