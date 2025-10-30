from django import forms
from django.db import connection
from django.utils import timezone
from .models import (
    Usuario, Rol, UsuarioRol, CargoArbitral, CuerpoArbitral,
    Login, Comuna
)

# =========================================
# FORMULARIO DE LOGIN
# =========================================
class LoginForm(forms.Form):
    rut = forms.CharField(
        label="RUT",
        max_length=12,
        widget=forms.TextInput(attrs={
            "placeholder": "Ej: 12345678-9",
            "class": "form-control"
        })
    )
    contrasena = forms.CharField(
        label="Contraseña",
        widget=forms.PasswordInput(attrs={
            "placeholder": "Contraseña",
            "class": "form-control"
        })
    )


# =========================================
# FORMULARIO DE REGISTRO DE USUARIO
# =========================================
class RegistroUsuarioForm(forms.Form):
    rut = forms.IntegerField(label="RUT (sin DV)")
    digitoV = forms.CharField(label="Dígito Verificador", max_length=1)
    nombre = forms.CharField(max_length=50)
    apellidoP = forms.CharField(label="Apellido Paterno", max_length=50)
    apellidoM = forms.CharField(label="Apellido Materno", max_length=50)
    telefono = forms.CharField(max_length=20)
    correo = forms.EmailField()
    direccion = forms.CharField(max_length=50, required=False)
    id_comuna = forms.ModelChoiceField(
        queryset=Comuna.objects.all().order_by("nombre"),
        label="Comuna",
        widget=forms.Select(attrs={"class": "form-control"})
    )
    contrasena = forms.CharField(
        widget=forms.PasswordInput(),
        label="Contraseña"
    )

    def save(self):
        data = self.cleaned_data

        # ✅ Crear usuario en la tabla usuarios
        usuario = Usuario.objects.create(
            rut=data["rut"],
            digitov=data["digitoV"].upper(),
            nombre=data["nombre"],
            apellidop=data["apellidoP"],
            apellidom=data["apellidoM"],
            telefono=data["telefono"],
            correo=data["correo"],
            direccion=data.get("direccion") or None,
            id_comuna=data["id_comuna"],
            id_club=None
        )

        # ✅ Crear login directamente con SQL
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO login (rut, digitov, contrasena, estado)
                VALUES (%s, %s, %s, %s);
            """, [usuario.rut, usuario.digitov, data["contrasena"], "activo"])

        return usuario


# =========================================
# FORMULARIO ASIGNAR ROL
# =========================================
class AsignarRolForm(forms.Form):
    # En tu template ya pintas rut/dv/activo a mano; el form solo provee el <select> de rol.
    rol = forms.ChoiceField(label="Rol")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        qs = (Rol.objects
                .exclude(nombre_rol__iexact="Sin rol")
                .exclude(nombre_rol__iexact="Dirigente")
                .order_by("nombre_rol")
                .values_list("rol_id", "nombre_rol"))

        choices = [("", "Seleccione un rol"), ("0", "Sin rol")]
        choices += [(str(rid), nombre) for rid, nombre in qs]

        if len(choices) == 2:
            choices.append(("","— No hay roles en BD —"))

        self.fields["rol"].choices = choices
        self.fields["rol"].widget.attrs.update({
            "id": "id_rol",
            "class": "form-control",
            "required": "required",
        })


# =========================================
# FORMULARIO EDITAR CARGO ARBITRAL
# =========================================
class EditarCargoArbitralForm(forms.Form):
    rut = forms.CharField(
        label="RUT del Árbitro",
        max_length=12,
        widget=forms.TextInput(attrs={
            "placeholder": "Ej: 20881482-6",
            "class": "form-control"
        })
    )

    id_cargo = forms.ModelChoiceField(
        label="Cargo Arbitral",
        queryset=CargoArbitral.objects.filter(nombre_cargo__in=[
            'Árbitro Central',
            'Asistente 1',
            'Asistente 2',
            'Cuarto Árbitro'
        ]).order_by("nombre_cargo"),
        widget=forms.Select(attrs={"class": "form-control"})
    )

    funcion = forms.CharField(
        label="Función adicional (opcional)",
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            "placeholder": "Ej: Árbitro principal",
            "class": "form-control"
        })
    )


# =========================================
# DISPONIBILIDAD DEL ÁRBITRO (Calendario)
# =========================================
DIAS_SEMANA = (
    (0, "Domingo"),
    (1, "Lunes"),
    (2, "Martes"),
    (3, "Miércoles"),
    (4, "Jueves"),
    (5, "Viernes"),
    (6, "Sábado"),
)

class DisponibilidadAgregarForm(forms.Form):
    dia_semana = forms.ChoiceField(
        choices=DIAS_SEMANA,
        label="Día",
        widget=forms.Select(attrs={"class": "form-control"})
    )
    franja_inicio = forms.TimeField(
        label="Desde",
        input_formats=["%H:%M"],
        widget=forms.TimeInput(
            format="%H:%M",
            attrs={"type": "time", "class": "form-control"}
        )
    )
    franja_fin = forms.TimeField(
        label="Hasta",
        input_formats=["%H:%M"],
        widget=forms.TimeInput(
            format="%H:%M",
            attrs={"type": "time", "class": "form-control"}
        )
    )

    def __init__(self, *args, rut=None, digitov=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.rut = rut
        self.digitov = (digitov or "").upper()

    def clean(self):
        cleaned = super().clean()
        dia = cleaned.get("dia_semana")
        ini = cleaned.get("franja_inicio")
        fin = cleaned.get("franja_fin")

        # Día → int 0..6
        try:
            dia = int(dia) if dia is not None else None
        except (TypeError, ValueError):
            dia = None

        if dia is None or dia not in range(0, 7):
            self.add_error("dia_semana", "Selecciona un día válido.")
            return cleaned

        if not ini or not fin:
            raise forms.ValidationError("Debes indicar horario de inicio y término.")

        if ini >= fin:
            raise forms.ValidationError("La hora de inicio debe ser menor que la de término.")

        # Validación de traslapes con registros ACTIVOS del mismo día
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT 1
                  FROM disponibilidad_arbitro
                 WHERE rut = %s
                   AND UPPER(digitov) = UPPER(%s)
                   AND dia_semana = %s
                   AND activo = TRUE
                   AND (%s < franja_fin) AND (%s > franja_inicio)
                 LIMIT 1;
            """, [
                self.rut,
                self.digitov,
                dia,
                ini.strftime("%H:%M"),
                fin.strftime("%H:%M"),
            ])
            if cursor.fetchone():
                raise forms.ValidationError(
                    "Ya tienes disponibilidad que se solapa en ese día/horario."
                )

        return cleaned


class DisponibilidadEliminarForm(forms.Form):
    disp_id = forms.IntegerField(widget=forms.HiddenInput())

    def __init__(self, *args, rut=None, digitov=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.rut = rut
        self.digitov = (digitov or "").upper()