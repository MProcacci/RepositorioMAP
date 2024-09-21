import flet as ft
import random
import string
import subprocess


"""
Programa para una aplicaccion de generador de contraseñas aleatorias, el usuario puede 
cambiar la longitud de la contraseña y el uso de mayúsculas, números y símbolos. El 
programa genera una contraseña aleatoria y la muestra en la interfaz de usuario. El 
programa puede copiar la contraseña al portapapeles al hacer clic en el botón.
"""


def ejecutar_gestor(e):
    # Ejecutar el gestor de contraseñas.
    result = subprocess.run(['python', 'password_manager.py'], capture_output=True, text=True)
    #result = subprocess.run(['password_manager.exe'], capture_output=True, text=True)
    return

# Función principal de la aplicación.
def main(page: ft.Page):
    page.title = "Password Generator"
    page.window.width = 600
    page.window.height = 500
    titulo = ft.Text("Generador de Contraseñas", size=32, weight=ft.FontWeight.BOLD)

    # Función para generar la contraseña aleatoria.
    def generate_password(length, use_uppercase, use_numbers, use_symbols):
        characters = string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    # Función para actualizar la contraseña cuando cambia el valor del slider.
    def update_password(e):
        password_field.value = generate_password(
            int(length_slider.value),
            uppercase_switch.value,
            numbers_switch.value,
            symbols_switch.value
        )
        page.update()

    # Función para copiar la contraseña al portapapeles
    def copy_to_clipboard(e):
        page.set_clipboard(password_field.value)
        snack_bar = ft.SnackBar(ft.Text("Contraseña copiada al portapapeles"))
        page.overlay.append(snack_bar)
        snack_bar.open = True
        page.update()

    # Crear el campo de texto para mostrar la contraseña.
    password_field = ft.TextField(
        read_only=True,
        width=400,
        text_align=ft.TextAlign.CENTER,
        text_style=ft.TextStyle(size=20, weight=ft.FontWeight.BOLD),
        border=ft.InputBorder.OUTLINE,
        border_color=ft.colors.BLUE_700,
    )

    # Crear el slider.
    length_slider = ft.Slider(
        min=8,
        max=32,
        divisions=24,
        value=12,
        label="{value}",
        on_change=update_password
    )

    # Crear los botones y switches de la interfaz de usuario.
    generate_button = ft.ElevatedButton("Generar Contraseña", on_click=update_password, icon=ft.icons.REFRESH)
    uppercase_switch = ft.Switch(label="Incluir Mayúsculas", value=True, on_change=update_password)
    numbers_switch = ft.Switch(label="Incluir Números", value=True, on_change=update_password)
    symbols_switch = ft.Switch(label="Incluir Símbolos", value=True, on_change=update_password)
    ejecutar_button = ft.ElevatedButton("Gestor de Contraseñas", on_click=ejecutar_gestor)

    # Crear el botón para copiar la contrasen��a al portapapeles.
    copy_button = ft.ElevatedButton("Copiar al Portapapeles",
                                    on_click=copy_to_clipboard,
                                    icon=ft.icons.COPY
                                    )


    # Añadir los controles a la página.
    page.add(ft.Row([titulo], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
             ft.Text("Longitud de la Contraseñas"),
             length_slider,
             ft.Row([password_field], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
             ft.Row([uppercase_switch, numbers_switch, symbols_switch], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
             ft.Row([generate_button, copy_button], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
             ft.Row([ejecutar_button], spacing=10, alignment=ft.MainAxisAlignment.CENTER)
             )

# Ejecutar la aplicación.
ft.app(target=main)


