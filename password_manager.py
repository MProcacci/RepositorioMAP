import flet as ft
import os
import datetime
from cryptography.fernet import Fernet
import hashlib

"""
Este script muestra cómo encriptar y desencriptar datos utilizando el algoritmo Fernet de cryptography.
También muestra cómo generar una clave de encriptación, almacenarla en un archivo y verificarla.

Para usar este script, necesitas instalar las bibliotecas flet y cryptography.
Puedes instalarlas con pip: 'pip install flet cryptography'

Para ver este script, simplemente ejecútelo en un entorno Python.

Para generar una clave de encriptación, puedes usar el siguiente programa: 'encrip_fernet.py'

Este script también incluye un ejemplo de cómo generar un hash de la clave de acceso para verificarla.

Para generar un hash de la clave de acceso, puedes usar el siguiente programa: 'hash_access_key.py'

"""

# Clave de encriptación (debe ser la misma para encriptar y desencriptar)
ENCRYPTION_KEY = b'_bP8Me6hC0KV6WV2nkIQWD7KW76muMaD-US9Pjr0NFc='  # Asegúrate de usar la clave correcta
cipher_suite = Fernet(ENCRYPTION_KEY)

# Función para encriptar datos
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode()).decode()

# Función para desencriptar datos
def decrypt_data(encrypted_data):
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        return f"Error al desencriptar: {e}"

# Nombre fijo del archivo de backup
BACKUP_FILENAME = "backup_claves.txt"

# Función para generar un hash de la clave de acceso
def hash_access_key(access_key):
    return hashlib.sha256(access_key.encode()).hexdigest()

# Clave de acceso hasheada
HASHED_ACCESS_KEY = hash_access_key("escualido29")

# Función para verificar la clave de acceso
def verify_access_key(access_key):
    return hash_access_key(access_key) == HASHED_ACCESS_KEY

# Función para almacenar una nueva contraseña
def store_password(site, user, password):
    encrypted_site = encrypt_data(site)
    encrypted_user = encrypt_data(user)
    encrypted_password = encrypt_data(password)
    date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    encrypted_date = encrypt_data(date)

    try:
        with open(BACKUP_FILENAME, 'a') as file:
            file.write(f"{encrypted_site},{encrypted_user},{encrypted_password},{encrypted_date}\n")
    except Exception as e:
        return str(e)
    return None

# Función para consultar contraseñas
def retrieve_passwords():
    passwords = []
    if os.path.exists(BACKUP_FILENAME):
        try:
            with open(BACKUP_FILENAME, 'r') as file:
                for line in file:
                    parts = line.strip().split(',')
                    if len(parts) == 4:
                        encrypted_site, encrypted_user, encrypted_password, encrypted_date = parts
                        site = decrypt_data(encrypted_site)
                        user = decrypt_data(encrypted_user)
                        password = decrypt_data(encrypted_password)
                        date = decrypt_data(encrypted_date)
                        if "Error al desencriptar" not in site and "Error al desencriptar" not in user and "Error al desencriptar" not in password and "Error al desencriptar" not in date:
                            passwords.append((site, user, password, date))
                        else:
                            print(f"Error al desencriptar línea: {line}")
                    else:
                        print(f"Línea incorrecta: {line}")
        except Exception as e:
            return str(e)
    return passwords

# Función para modificar una contraseña
def modify_password(site, user, new_password):
    passwords = retrieve_passwords()
    if isinstance(passwords, str):
        return passwords

    for i, (stored_site, _, _, _) in enumerate(passwords):
        if stored_site == site:
            passwords[i] = (site, user, new_password, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            break

    try:
        with open(BACKUP_FILENAME, 'w') as file:
            for site, user, password, date in passwords:
                encrypted_site = encrypt_data(site)
                encrypted_user = encrypt_data(user)
                encrypted_password = encrypt_data(password)
                encrypted_date = encrypt_data(date)
                file.write(f"{encrypted_site},{encrypted_user},{encrypted_password},{encrypted_date}\n")
    except Exception as e:
        return str(e)
    return None

# Función para eliminar una contraseña
def delete_password(site):
    passwords = retrieve_passwords()
    if isinstance(passwords, str):
        return passwords

    passwords = [entry for entry in passwords if entry[0] != site]

    try:
        with open(BACKUP_FILENAME, 'w') as file:
            for site, user, password, date in passwords:
                encrypted_site = encrypt_data(site)
                encrypted_user = encrypt_data(user)
                encrypted_password = encrypt_data(password)
                encrypted_date = encrypt_data(date)
                file.write(f"{encrypted_site},{encrypted_user},{encrypted_password},{encrypted_date}\n")
    except Exception as e:
        return str(e)
    return None

# Función para reiniciar los campos de texto
def reset_fields(site_input, user_input, password_input, new_password_input, page):
    site_input.value = ""
    user_input.value = ""
    password_input.value = ""
    new_password_input.value = ""
    page.update()

# Funcion para deshabilitar
def disable_field(field, page):
    field.disabled = True
    update_ui(page)

# Función para habilitar
def enable_field(field, page):
    field.disabled = False
    update_ui(page)

# Función para actualizar la interfaz
def update_ui(page):
    page.update()

# Función para mostrar un cuadro de diaño
def show_dialog(page: ft.Page, dialog: ft.AlertDialog):
    page.dialog = dialog
    dialog.open = True
    page.update()

# Función para cerrar un cuadro de diálogo
def close_dialog(page: ft.Page, dialog: ft.AlertDialog):
    dialog.open = False
    page.dialog = None
    page.update()

# Función principal
def main(page: ft.Page):
    page.title = "Gestor de Contraseñas"
    page.window.width = 800
    page.window.height = 710
    titulo = ft.Text("Gestor de Contraseñas", size=32, weight=ft.FontWeight.BOLD)
    page.vertical_alignment = ft.MainAxisAlignment.CENTER

    # Crear los campos de entrada de texto
    access_key_input = ft.TextField(label="Clave de Acceso",
                                    password=True, width=500,
                                    border_color="cyan")
    site_input = ft.TextField(label="Sitio/App",
                              width=500,
                              border_color="cyan",
                              disabled=True)
    user_input = ft.TextField(label="Usuario",
                              width=500,
                              border_color="cyan",
                              disabled=True)
    password_input = ft.TextField(label="Contraseña",
                                  password=True,
                                  width=500,
                                  border_color="cyan",
                                  disabled=True)
    new_password_input = ft.TextField(label="Nueva Contraseña",
                                      password=True,
                                      width=500,
                                      border_color="cyan",
                                      disabled=True)
    result_text = ft.Text()

    # Funciones de verificación de acceso.
    def verify_access(e):
        if verify_access_key(access_key_input.value):
            access_key_input.visible = False
            site_input.visible = True
            user_input.visible = True
            password_input.visible = True
            new_password_input.visible = True
            result_text.value = "Acceso concedido"
            enable_field(site_input, page)
            enable_field(user_input, page)
            enable_field(password_input, page)
            enable_field(new_password_input, page)
            page.update()
        else:
            result_text.value = "Clave de acceso incorrecta"
            page.update()

    # Funciones para la gestión de contrasenias
    def store_password_action(e):
        if not verify_access_key(access_key_input.value):
            result_text.value = "Clave de acceso incorrecta"
            page.update()
            return
        site = site_input.value
        user = user_input.value
        password = password_input.value
        if site == "" or user == "" or password == "":
            result_text.value = "Debe ingresar un sitio, un usuario y una contraseña"
            page.update()
            return
        error = store_password(site_input.value, user_input.value, password_input.value)
        if error:
            result_text.value = f"Error al almacenar la contraseña: {error}"
        else:
            result_text.value = f"Contraseña para {site_input.value} almacenada"
        reset_fields(site_input, user_input, password_input, new_password_input, page)

    # Función para la lista de contrasenias
    def list_passwords_action(e):
        if not verify_access_key(access_key_input.value):
            result_text.value = "Clave de acceso incorrecta"
            page.update()
            return

        passwords = retrieve_passwords()
        if isinstance(passwords, str):
            result_text.value = f"Error al recuperar contraseñas: {passwords}"
            page.update()
            return

        password_items = [ft.Text(f"{site}:\t\t{user}\t\t{password}\t\t(Fecha:{date})")
                          for site, user, password, date in passwords]

        def close_dialog1(e):
            e.control.page.dialog.open = False
            e.control.page.update()

        def print_passwords(e):
            try:
                with open('listado_claves.txt', 'w') as f:
                    for site, user, password, date in passwords:
                        f.write(f"{site}:\t\t\t\t\t{user}\t\t\t\t\t{password}\t\t\t\t\t(Fecha:{date})\n")

                result_text.value = "La lista de claves ha sido guardada en 'listado_claves.txt'"
                page.dialog.open = False
                page.update()
            except Exception as error:
                result_text.value = f"Error al guardar el archivo: {str(error)}"
                page.update()

        dialog = ft.AlertDialog(
            title=ft.Text("Contraseñas Almacenadas", text_align=ft.TextAlign.CENTER),
            content=ft.ListView(
                controls=password_items,
                expand=1,
                spacing=10,
                padding=20,
                width=700,
            ),
            actions=[
                ft.TextButton("Imprimir", on_click=print_passwords),
                ft.TextButton("Cerrar", on_click=close_dialog1)
            ],
        )

        page.dialog = dialog
        dialog.open = True
        page.update()
        reset_fields(site_input, user_input, password_input, new_password_input, page)

    # Función para la recuperación de contrasenias
    def retrieve_password_action(e):
        if not verify_access_key(access_key_input.value):
            result_text.value = "Clave de acceso incorrecta"
            page.update()
            return

        site = site_input.value
        passwords = retrieve_passwords()
        if site == "":
            result_text.value = "Debe ingresar un sitio"
            page.update()
            return
        if isinstance(passwords, str):
            result_text.value = f"Error al recuperar contraseñas: {passwords}"
        else:
            for stored_site, user, password, date in passwords:
                if stored_site == site:
                    result_text.value = f"{site}: {user} {password} (Fecha: {date})"
                    break
            else:
                result_text.value = f"No se encontró una contraseña para {site}"
        reset_fields(site_input, user_input, password_input, new_password_input, page)

    # Función para la modificación de contrasenias
    def modify_password_action(e):
        if not verify_access_key(access_key_input.value):
            result_text.value = "Clave de acceso incorrecta"
            page.update()
            return

        site = site_input.value
        user = user_input.value
        password = password_input.value
        new_password = new_password_input.value
        if site == "" or user == "" or password == "" or new_password == "":
            result_text.value = "Debe ingresar un sitio, un usuario, una contraseña y una nueva contraseña"
            page.update()
            return

        passwords = retrieve_passwords()
        for stored_site, store_user, clave, date in passwords:
            if stored_site == site and store_user == user:
                if password == new_password:
                    result_text.value = f"La nueva contraseña para {site} es la misma que la actual"
                    reset_fields(site_input, user_input, password_input, new_password_input, page)
                    return
                elif clave != password:
                    result_text.value = f"La contraseña actual para {site} es incorrecta"
                    reset_fields(site_input, user_input, password_input, new_password_input, page)
                    return
                else:
                    break

        error = modify_password(site, user, new_password)
        if error:
            result_text.value = f"Error al modificar la contraseña: {error}"
        else:
            result_text.value = f"Contraseña para {site} modificada"
        reset_fields(site_input, user_input, password_input, new_password_input, page)

    # Función para la eliminación de contrasenias
    def delete_password_action(e):
        if not verify_access_key(access_key_input.value):
            result_text.value = "Clave de acceso incorrecta"
            e.page.update()
            return

        site = site_input.value
        user = user_input.value
        password = password_input.value
        if site == "" or user == "" or password == "":
            result_text.value = "Debe ingresar un sitio, un usuario y una contraseña"
            e.page.update()
            return

        passwords = retrieve_passwords()
        for stored_site, store_user, clave, date in passwords:
            if stored_site == site and store_user == user:
                if clave != password:
                    result_text.value = f"La contraseña actual para {site} es incorrecta"
                    reset_fields(site_input, user_input, password_input, new_password_input, page)
                    return
                else:
                    break

        # Función para confirmar la eliminación
        def confirm_delete(e):
            error = delete_password(site)
            if error:
                result_text.value = f"Error al eliminar la contraseña: {error}"
            else:
                result_text.value = f"Contraseña para {site} eliminada"
            reset_fields(site_input, user_input, password_input, new_password_input, e.page)
            close_dialog(e.page, e.page.dialog)

        # Función para cancelar la eliminación
        def cancel_delete(e):
            result_text.value = "Eliminación cancelada"
            reset_fields(site_input, user_input, password_input, new_password_input, e.page)
            close_dialog(e.page, e.page.dialog)

        dialog = ft.AlertDialog(
            title=ft.Text("Confirmar Eliminación"),
            content=ft.Text(f"¿Estás seguro de que deseas eliminar la contraseña para {site}?"),
            actions=[
                ft.TextButton("Sí", on_click=confirm_delete),
                ft.TextButton("No", on_click=cancel_delete)
            ],
            actions_alignment=ft.MainAxisAlignment.END
        )

        show_dialog(e.page, dialog)

    # Creamos los Botones.
    almacenar_contraseña = ft.ElevatedButton("Almacenar Contraseña", on_click=store_password_action)
    listar_contraseñas = ft.ElevatedButton("Listar Contraseñas", on_click=list_passwords_action)
    consultar_contraseña = ft.ElevatedButton("Consultar Contraseña", on_click=retrieve_password_action)
    modificar_contraseña = ft.ElevatedButton("Modificar Contraseña", on_click=modify_password_action)
    eliminar_contraseña = ft.ElevatedButton("Eliminar Contraseña", on_click=delete_password_action)

    # Añadimos los botones y los controles a la página.
    page.add(ft.Row([titulo], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
        access_key_input,
        ft.ElevatedButton("Verificar Acceso", on_click=verify_access),
        site_input,
        user_input,
        password_input,
        new_password_input,
        ft.Row([almacenar_contraseña], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([listar_contraseñas], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([consultar_contraseña], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([modificar_contraseña], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
        ft.Row([eliminar_contraseña], spacing=10, alignment=ft.MainAxisAlignment.CENTER),
        result_text
    )

# Inicializamos la interfaz gráfica.
ft.app(target=main)
