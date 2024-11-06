import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from tkinter import ttk
from tkinter.ttk import Button
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import json
import hashlib
import os
from datetime import datetime
from PIL import Image, ImageTk

# Ruta del archivo donde se almacenan los usuarios registrados
USER_FILE = r"C:\Users\mauri\OneDrive\Desktop\usuarios_PRO_FIN.txt"
# Rutas de archivos de claves públicas y privadas para RSA
PUBLIC_KEY_FILE = r"C:\Users\mauri\OneDrive\Desktop\public_key.pem"
PRIVATE_KEY_FILE = r"C:\Users\mauri\OneDrive\Desktop\private_key.pem"

# Función para hash de contraseñas usando SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Funciones de cifrado y descifrado con DES
def encrypt_file(file_data, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)  # Crear cifrador DES en modo ECB
    padded_data = pad(file_data.encode('utf-8'), DES.block_size)  # Añadir padding al contenido
    encrypted_data = des.encrypt(padded_data)  # Cifrar el contenido con DES
    return encrypted_data

def decrypt_file(encrypted_data, key):
    des = DES.new(key.encode('utf-8'), DES.MODE_ECB)  # Crear cifrador DES en modo ECB
    decrypted_padded_data = des.decrypt(encrypted_data)  # Descifrar el contenido
    try:
        decrypted_data = unpad(decrypted_padded_data, DES.block_size)  # Eliminar padding
        return decrypted_data.decode('utf-8')
    except ValueError as e:
        print(f"Error de desencriptación o padding incorrecto: {e}")
        return None

# Funciones para cifrado y descifrado de contraseñas individuales usando RSA
def load_rsa_keys():
    with open(PUBLIC_KEY_FILE, 'rb') as pub_file:
        public_key = RSA.import_key(pub_file.read())  # Cargar clave pública
    with open(PRIVATE_KEY_FILE, 'rb') as priv_file:
        private_key = RSA.import_key(priv_file.read())  # Cargar clave privada
    return public_key, private_key

def encrypt_password_with_rsa(password, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)  # Cifrado RSA con padding OAEP
    encrypted_password = cipher_rsa.encrypt(password.encode('utf-8'))  # Cifrar contraseña
    return encrypted_password

def decrypt_password_with_rsa(encrypted_password, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)  # Descifrado RSA con padding OAEP
    decrypted_password = cipher_rsa.decrypt(encrypted_password)  # Descifrar contraseña
    return decrypted_password.decode('utf-8')

# Cargar claves RSA para usar en el programa
public_key, private_key = load_rsa_keys()

# Clase para la ventana de búsqueda
class SearchWindow:
    def __init__(self, master, search_callback):
        self.top = tk.Toplevel(master)
        self.top.title("Buscar por campo")
        self.top.configure(bg="#E0F7FA")  # Fondo azul claro
        self.top.geometry("500x300")  # Tamaño más grande
        self.search_callback = search_callback

        # Campo de selección de búsqueda
        tk.Label(self.top, text="Campo:", bg="#E0F7FA").grid(row=0, column=0, padx=10, pady=10)
        self.field_choice = ttk.Combobox(self.top, values=[
            "Nombre del sitio", "Usuario", "Contraseña", "URL", "Notas", "Etiquetas"
        ])
        self.field_choice.grid(row=0, column=1, padx=10, pady=10)
        self.field_choice.current(0)  # Valor por defecto

        # Campo de entrada para el término de búsqueda
        tk.Label(self.top, text="Buscar:", bg="#E0F7FA").grid(row=1, column=0, padx=10, pady=10)
        self.search_entry = tk.Entry(self.top, width=30)
        self.search_entry.grid(row=1, column=1, padx=10, pady=10)

        # Botones para buscar y cerrar la ventana
        search_button = tk.Button(self.top, text="Buscar", bg="#00796B", fg="white", command=self.perform_search)
        search_button.grid(row=2, column=0, padx=10, pady=20)
        return_button = tk.Button(self.top, text="Regresar", bg="#00796B", fg="white", command=self.top.destroy)
        return_button.grid(row=2, column=1, padx=10, pady=20)

    def perform_search(self):
        if self.search_callback is None:
            messagebox.showerror("Error", "No se pudo realizar la búsqueda.")
            return

        field = self.field_choice.get()  # Obtener campo de búsqueda seleccionado
        search_term = self.search_entry.get().strip()  # Obtener término de búsqueda
        if not search_term:
            messagebox.showwarning("Advertencia", "Por favor ingrese un término de búsqueda.")
            return

        print(f"Realizando búsqueda en {field} con término '{search_term}'")  # Mensaje de depuración
        self.search_callback(field, search_term)  # Ejecutar búsqueda en PasswordManagerApp
        self.top.destroy()  # Cerrar la ventana de búsqueda

# Clase para la ventana de registro de usuario
class RegisterWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Registro de Usuario")
        self.master.configure(bg="#E8F5E9")  # Fondo verde claro
        self.master.geometry("400x250")  # Tamaño más grande

        # Estilo de etiquetas y entradas
        tk.Label(master, text="Usuario:", bg="#E8F5E9").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(master, text="Contraseña:", bg="#E8F5E9").grid(row=1, column=0, padx=10, pady=10)

        # Campos de entrada para usuario y contraseña
        self.username = tk.Entry(master)
        self.password = tk.Entry(master, show='*')  # Ocultar contraseña
        self.username.grid(row=0, column=1, padx=10, pady=10)
        self.password.grid(row=1, column=1, padx=10, pady=10)

        # Botón para registrar usuario
        tk.Button(master, text="Registrar", bg="#00796B", fg="white", command=self.register_user).grid(
            row=2, column=0, columnspan=2, pady=20)

    def register_user(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showwarning("Error", "Por favor, complete todos los campos.")
            return

        hashed_password = hash_password(password)  # Hash de la contraseña

        # Guardar usuario en el archivo de usuarios
        with open(USER_FILE, "a") as f:
            f.write(f"{username},{hashed_password}\n")

        messagebox.showinfo("Registro Exitoso", "Usuario registrado correctamente.")
        self.master.destroy()  # Cerrar ventana de registro


# Clase para la ventana de inicio de sesión
class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Inicio de Sesión")
        self.master.configure(bg="#E0F7FA")  # Fondo azul claro
        self.master.geometry("400x250")  # Tamaño más grande

        # Estilo de etiquetas y entradas
        tk.Label(master, text="Usuario:", bg="#E0F7FA").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(master, text="Contraseña:", bg="#E0F7FA").grid(row=1, column=0, padx=10, pady=10)

        # Campos de entrada para usuario y contraseña
        self.username = tk.Entry(master)
        self.password = tk.Entry(master, show='*')
        self.username.grid(row=0, column=1, padx=10, pady=10)
        self.password.grid(row=1, column=1, padx=10, pady=10)

        # Botón para iniciar sesión
        tk.Button(master, text="Iniciar Sesión", bg="#00796B", fg="white", command=self.login_user).grid(
            row=2, column=0, columnspan=2, pady=20)

        tk.Button(master, text="Registrar", command=self.open_register_window).grid(row=3, column=0, columnspan=2)

    def open_register_window(self):
        register_window = tk.Toplevel(self.master)  # Crear ventana de registro
        RegisterWindow(register_window)  # Iniciar ventana de registro

    def login_user(self):
        username = self.username.get().strip()
        password = self.password.get().strip()
        hashed_password = hash_password(password)

        # Verificar las credenciales de usuario en el archivo de usuarios
        if os.path.exists(USER_FILE):
            with open(USER_FILE, "r") as f:
                users = f.readlines()
                for user in users:
                    stored_username, stored_password = user.strip().split(',')
                    if stored_username == username and stored_password == hashed_password:
                        messagebox.showinfo("Éxito", "Inicio de sesión exitoso.")
                        self.open_password_manager()  # Abrir gestor de contraseñas
                        return
                messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
        else:
            messagebox.showerror("Error", "No hay usuarios registrados. Por favor, registre un usuario.")

    def open_password_manager(self):
        self.master.destroy()  # Cerrar ventana de login
        root = tk.Tk()
        PasswordManagerApp(root)
        root.mainloop()

# Clase para la gestión de contraseñas
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Gestión de Contraseñas")
        self.root.configure(bg="#E0F7FA")  # Fondo azul claro
        self.root.geometry("800x600")  # Tamaño más grande para ocupar más espacio en pantalla


        self.passwords = []  # Lista para almacenar las contraseñas

        # Configuración de tiempo en segundos para limpiar el portapapeles y bloquear la aplicación
        self.clipboard_timeout = 30  # Tiempo predeterminado: 30 segundos
        self.inactivity_timeout = 60  # Tiempo predeterminado: 60 segundos

        # Variables de la interfaz y otros parámetros
        self.site_name = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.url = tk.StringVar()
        self.notes = tk.StringVar()
        self.extra1 = tk.StringVar()
        self.extra2 = tk.StringVar()
        self.extra3 = tk.StringVar()
        self.extra4 = tk.StringVar()
        self.extra5 = tk.StringVar()
        self.tags = tk.StringVar()
        self.icon = tk.StringVar()
        self.expiration_date = tk.StringVar()
        self.master_key = "mysecret"  # Clave maestra predeterminada
        self.current_id = 1
        self.search_var = tk.StringVar()

        # Configuración del temporizador de inactividad
        self.inactivity_timer = None
        self.setup_inactivity_timer()

        # Crear la interfaz gráfica
        self.create_widgets()
        
    def change_master_key(self):
        # Permite cambiar la clave maestra de 8 caracteres mediante una entrada de diálogo
        new_key = simpledialog.askstring("Cambiar Clave Maestra", "Ingrese la nueva clave (8 caracteres):", show="*")
        if new_key and len(new_key) == 8:
            self.master_key = new_key
            messagebox.showinfo("Clave actualizada", "La clave maestra se ha cambiado correctamente.")
        else:
            messagebox.showerror("Error", "La clave debe tener exactamente 8 caracteres.")

    def create_widgets(self):
        # Crear la interfaz principal con campos de entrada
        main_frame = tk.Frame(self.root, bg="#E0F7FA")
        main_frame.pack(pady=10)

        # Campos de entrada para los detalles de la contraseña
        tk.Label(main_frame, text="Nombre del sitio:", bg="#E0F7FA").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        tk.Entry(main_frame, textvariable=self.site_name, width=30).grid(row=0, column=1, padx=10, pady=5)

        tk.Label(main_frame, text="Usuario:", bg="#E0F7FA").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        tk.Entry(main_frame, textvariable=self.username, width=30).grid(row=1, column=1, padx=10, pady=5)

        tk.Label(main_frame, text="Contraseña:", bg="#E0F7FA").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = tk.Entry(main_frame, textvariable=self.password, width=30)
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)

        tk.Label(main_frame, text="URL:", bg="#E0F7FA").grid(row=3, column=0, padx=10, pady=5, sticky="e")
        tk.Entry(main_frame, textvariable=self.url, width=30).grid(row=3, column=1, padx=10, pady=5)

        tk.Label(main_frame, text="Notas:", bg="#E0F7FA").grid(row=4, column=0, padx=10, pady=5, sticky="e")
        tk.Entry(main_frame, textvariable=self.notes, width=30).grid(row=4, column=1, padx=10, pady=5)

        # Campos adicionales opcionales
        for i, (label_text, var) in enumerate([("Extra 1:", self.extra1), ("Extra 2:", self.extra2),
                                               ("Extra 3:", self.extra3), ("Extra 4:", self.extra4),
                                               ("Extra 5:", self.extra5)], start=5):
            tk.Label(main_frame, text=label_text, bg="#E0F7FA").grid(row=i, column=0, padx=10, pady=5, sticky="e")
            tk.Entry(main_frame, textvariable=var, width=30).grid(row=i, column=1, padx=10, pady=5)

        # Campos para etiquetas, icono y fecha de vencimiento
        tk.Label(main_frame, text="Etiquetas:", bg="#E0F7FA").grid(row=10, column=0, padx=10, pady=5, sticky="e")
        tk.Entry(main_frame, textvariable=self.tags, width=30).grid(row=10, column=1, padx=10, pady=5)

        tk.Label(main_frame, text="Ícono (nombre):", bg="#E0F7FA").grid(row=11, column=0, padx=10, pady=5, sticky="e")
        self.icon_entry = tk.Entry(main_frame, textvariable=self.icon, width=25)
        self.icon_entry.grid(row=11, column=1, padx=10, pady=5)
        tk.Button(main_frame, text="Seleccionar Icono", bg="#00796B", fg="white", command=self.select_icon).grid(row=11, column=2, padx=10, pady=5, sticky="w")


        tk.Label(main_frame, text="Fecha de vencimiento (YYYY-MM-DD):", bg="#E0F7FA").grid(row=12, column=0, padx=10, pady=5, sticky="e")
        tk.Entry(main_frame, textvariable=self.expiration_date, width=30).grid(row=12, column=1, padx=10, pady=5)
        self.expiration_date.set("2025-12-31")  # Fecha por defecto

        # Botones para gestionar contraseñas
        button_frame = tk.Frame(self.root, bg="#E0F7FA")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Añadir", bg="#00796B", fg="white", command=self.add_entry).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(button_frame, text="Guardar Archivo", bg="#00796B", fg="white", command=self.save_file).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(button_frame, text="Actualizar Campos", bg="#00796B", fg="white", command=self.update_entry).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(button_frame, text="Configurar Tiempos", bg="#00796B", fg="white", command=self.configure_times).grid(row=0, column=3, padx=5, pady=5)
        tk.Button(button_frame, text="Copiar Selección", bg="#00796B", fg="white", command=self.copy_selected_entry).grid(row=0, column=4, padx=5, pady=5)

        tk.Button(button_frame, text="Cargar Archivo", bg="#00796B", fg="white", command=self.load_file).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(button_frame, text="Cambiar Clave Maestra", bg="#00796B", fg="white", command=self.change_master_key).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(button_frame, text="Exportar", bg="#00796B", fg="white", command=self.export_to_plain_text).grid(row=1, column=2, padx=5, pady=5)
        tk.Button(button_frame, text="Importar", bg="#00796B", fg="white", command=self.import_from_plain_text).grid(row=1, column=3, padx=5, pady=5)
        
        # Área de imagen
        self.icon_label = tk.Label(main_frame, bg="#E0F7FA")
        self.icon_label.grid(row=12, column=1, columnspan=2, padx=10, pady=5, sticky="e")
        
        # Botón para copiar solo el usuario
        tk.Button(button_frame, text="Copiar Usuario", bg="#00796B", fg="white", command=self.copy_username).grid(row=2, column=0, padx=5, pady=5)

        # Botón para copiar solo la contraseña
        tk.Button(button_frame, text="Copiar Contraseña", bg="#00796B", fg="white", command=self.copy_password).grid(row=2, column=1, padx=5, pady=5)


        # Área de lista para mostrar las contraseñas
        list_frame = tk.Frame(self.root, bg="#E0F7FA")
        list_frame.pack(pady=10, padx=10, fill="x")

        self.password_listbox = tk.Listbox(list_frame, height=10, width=50)
        self.password_listbox.pack(side="left", fill="y", padx=10, pady=10)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        scrollbar.config(command=self.password_listbox.yview)
        scrollbar.pack(side="right", fill="y")

        self.password_listbox.config(yscrollcommand=scrollbar.set)

        # Botón para abrir la ventana de búsqueda
        tk.Button(main_frame, text="Buscar por campo", bg="#00796B", fg="white", command=self.open_search_window).grid(row=0, column=3, padx=10, pady=5, sticky="w")
        
        self.password_listbox.bind("<<ListboxSelect>>", self.load_selected_entry)


    def select_icon(self):
        """Abre un diálogo para seleccionar una imagen y la muestra en la interfaz."""
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif")])
        if not file_path:
            return  # Si no se seleccionó ningún archivo, salir

        # Actualizar el campo de entrada con el nombre del archivo
        icon_name = file_path.split('/')[-1]  # Obtener solo el nombre del archivo
        self.icon.set(icon_name)

        # Guardar la ruta completa de la imagen seleccionada
        self.current_icon_path = file_path

        # Cargar y mostrar el icono
        self.display_icon(file_path)

        
    def display_icon(self, file_path):
        """Muestra la imagen seleccionada en el Label de icono, o muestra un mensaje si no se encuentra."""
        if not os.path.isfile(file_path):  # Verificar si el archivo existe
            # Si la imagen no existe, mostrar el mensaje de error en el Label
            self.icon_label.config(image='', text="No se encuentra la imagen", font=("Arial", 10), fg="red")
            self.icon_label.image = None  # Eliminar referencia a la imagen
            return

        try:
            # Abrir y redimensionar la imagen para ajustarla al tamaño del Label
            img = Image.open(file_path)
            img = img.resize((50, 50), Image.LANCZOS)  # Cambiar el tamaño de la imagen a 50x50
            self.icon_image = ImageTk.PhotoImage(img)  # Convertir a un formato que tkinter puede mostrar

            # Mostrar la imagen en el Label y limpiar cualquier mensaje de texto
            self.icon_label.config(image=self.icon_image, text="")  # Limpiar el texto si se encuentra la imagen
            self.icon_label.image = self.icon_image  # Mantener una referencia para evitar el garbage collection
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cargar la imagen: {e}")


    def open_search_window(self):
        # Abrir ventana de búsqueda de entradas
        SearchWindow(self.root, self.search_by_field)

    def search_by_field(self, field, search_term):
        """Realiza una búsqueda en el campo seleccionado y muestra los resultados en el Listbox."""
        # Mapa del campo de búsqueda al campo de datos
        field_map = {
            "Nombre del sitio": "site_name",
            "Usuario": "username",
            "Contraseña": "password",
            "URL": "url",
            "Notas": "notes",
            "Etiquetas": "tags"
        }
        search_key = field_map.get(field)

        if not search_key:
            messagebox.showerror("Error", "Campo de búsqueda no válido.")
            return

        # Realizar la búsqueda
        search_term = search_term.lower()
        results = []

        for entry in self.passwords:
            # Obtener el valor correspondiente al campo de búsqueda
            entry_value = ""
            if search_key == "tags":
                entry_value = " ".join(entry.get("tags", [])).lower()  # Concatenar todas las etiquetas
            else:
                entry_value = str(entry.get(search_key, "")).lower()

            # Verificar si el término de búsqueda está en el valor
            if search_term in entry_value:
                results.append(f"{entry['site_name']} ({entry['username']})")

        # Actualizar el Listbox con los resultados de búsqueda
        self.password_listbox.delete(0, tk.END)
        for result in results:
            self.password_listbox.insert(tk.END, result)

        # Crear el botón "Mostrar Todo" después de una búsqueda
        if not hasattr(self, 'show_all_button'):
            self.show_all_button = tk.Button(self.root, text="Mostrar Todo", bg="#00796B", fg="white", command=self.show_all_entries)
            self.show_all_button.pack(pady=10)
        self.show_all_button.lift()  # Traer el botón al frente en caso de estar oculto
        
    def show_all_entries(self):
        """Restaura el contenido completo del Listbox y oculta el botón 'Mostrar Todo'."""
        self.update_password_listbox()  # Llama al método para llenar el Listbox completo
        if hasattr(self, 'show_all_button'):
            self.show_all_button.pack_forget()  # Ocultar el botón "Mostrar Todo"

    def load_selected_entry(self, event):
        selected_index = self.password_listbox.curselection()
        if not selected_index:
            return  # No hacer nada si no hay selección

        entry_index = selected_index[0]
        entry = self.passwords[entry_index]

        # Actualizar los campos de entrada
        self.site_name.set(entry["site_name"])
        self.username.set(entry["username"])
        
        # Desencriptar la contraseña si es necesario
        try:
            decrypted_password = decrypt_password_with_rsa(bytes.fromhex(entry["password"]), private_key)
            self.password.set(decrypted_password)
            self.password_entry.config(show='')  # Mostrarla en texto plano
        except ValueError:
            self.password.set(entry["password"])
            self.password_entry.config(show='')

        # Actualizar los demás campos
        self.url.set(entry["url"])
        self.notes.set(entry["notes"])
        self.extra1.set(entry["extra_fields"].get("extra1", ""))
        self.extra2.set(entry["extra_fields"].get("extra2", ""))
        self.extra3.set(entry["extra_fields"].get("extra3", ""))
        self.extra4.set(entry["extra_fields"].get("extra4", ""))
        self.extra5.set(entry["extra_fields"].get("extra5", ""))
        self.tags.set(", ".join(entry["tags"]))

        # Actualizar el campo del icono
        icon_path = entry.get("icon", "")
        self.icon.set(icon_path.split('/')[-1])  # Solo el nombre del archivo
        if icon_path:
            self.display_icon(icon_path)  # Cargar y mostrar el icono
        else:
            self.icon_label.config(image='')  # Limpiar el icono si no hay uno guardado



    def update_entry(self):
        """Actualiza la entrada seleccionada con los datos de los campos de entrada."""
        selected_index = self.password_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Actualizar Campos", "No hay ninguna entrada seleccionada.")
            return

        # Obtener la entrada seleccionada y actualizar sus datos
        entry_index = selected_index[0]
        entry = self.passwords[entry_index]

        # Actualizar la información de la entrada con los datos actuales de los campos
        entry["site_name"] = self.site_name.get()
        entry["username"] = self.username.get()

        # Encriptar la contraseña si es necesario
        entry["password"] = encrypt_password_with_rsa(self.password.get(), public_key).hex() if self.password.get() else entry["password"]

        entry["url"] = self.url.get()
        entry["notes"] = self.notes.get()
        entry["extra_fields"] = {
            "extra1": self.extra1.get(),
            "extra2": self.extra2.get(),
            "extra3": self.extra3.get(),
            "extra4": self.extra4.get(),
            "extra5": self.extra5.get()
        }
        entry["tags"] = self.tags.get().split(", ")
        entry["expiration_date"] = f"{self.expiration_date.get()}T23:59:59Z"

        # Actualizar el icono si hay un archivo seleccionado
        if hasattr(self, 'current_icon_path') and os.path.isfile(self.current_icon_path):
            entry["icon"] = self.current_icon_path
        else:
            entry["icon"] = ""

        # Actualizar la lista visual de contraseñas
        self.update_password_listbox()

        # Mostrar mensaje de confirmación
        messagebox.showinfo("Actualizar Campos", "La entrada ha sido actualizada.")


    def toggle_search_section(self):
        """Alterna entre mostrar la sección de búsqueda y la interfaz principal."""
        if self.main_frame.winfo_ismapped():
            # Oculta la interfaz principal y muestra la sección de búsqueda
            self.main_frame.pack_forget()
            self.search_frame.pack()
            self.search_label.grid(row=0, column=0)
            self.search_entry.grid(row=0, column=1)
            self.search_button.grid(row=0, column=2)
        else:
            # Muestra la interfaz principal y oculta la sección de búsqueda
            self.search_frame.pack_forget()
            self.main_frame.pack()
         
    def setup_inactivity_timer(self):
        """Configura el temporizador de inactividad para bloquear la aplicación después del tiempo configurado."""
        if self.inactivity_timer:
            self.root.after_cancel(self.inactivity_timer)  # Cancela el temporizador anterior si existe
        # Configura el temporizador para bloquear la app tras el tiempo de inactividad
        self.inactivity_timer = self.root.after(self.inactivity_timeout * 1000, self.lock_app)

    def lock_app(self):
        """Bloquea la aplicación después de un período de inactividad."""
        messagebox.showinfo("Bloqueo Automático", "La aplicación se ha bloqueado por inactividad.")
        self.root.withdraw()  # Oculta la ventana principal
        LoginWindow(tk.Toplevel(self.root))  # Abre la ventana de inicio de sesión

    def configure_times(self):
        """Permite al usuario configurar los tiempos de limpieza del portapapeles y de inactividad."""
        # Pedir al usuario el tiempo para limpiar el portapapeles
        self.clipboard_timeout = simpledialog.askinteger("Configurar Tiempo de Limpieza", 
                                                         "Tiempo para limpiar el portapapeles (segundos):", 
                                                         initialvalue=self.clipboard_timeout, minvalue=5)
        # Pedir el tiempo para bloqueo por inactividad
        self.inactivity_timeout = simpledialog.askinteger("Configurar Tiempo de Bloqueo", 
                                                          "Tiempo para bloqueo de inactividad (segundos):", 
                                                          initialvalue=self.inactivity_timeout, minvalue=10)
        self.setup_inactivity_timer()  # Reinicia el temporizador de inactividad con los valores nuevos
        
       
    def copy_username(self):
        """Copia el usuario de la entrada seleccionada al portapapeles."""
        selected_index = self.password_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Copiar Usuario", "No se ha seleccionado ningún elemento para copiar el usuario.")
            return

        # Obtener la entrada seleccionada y el usuario
        entry_index = selected_index[0]
        entry = self.passwords[entry_index]
        username = entry["username"]

        # Copiar el usuario al portapapeles
        self.copy_to_clipboard(f"Usuario: {username}")

    def copy_password(self):
        """Copia la contraseña de la entrada seleccionada al portapapeles."""
        selected_index = self.password_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Copiar Contraseña", "No se ha seleccionado ningún elemento para copiar la contraseña.")
            return

        # Obtener la entrada seleccionada y desencriptar la contraseña, si es necesario
        entry_index = selected_index[0]
        entry = self.passwords[entry_index]
        try:
            decrypted_password = decrypt_password_with_rsa(bytes.fromhex(entry["password"]), private_key)
        except ValueError:
            decrypted_password = entry["password"]  # Usar contraseña en texto plano si no está encriptada

        # Copiar la contraseña al portapapeles
        self.copy_to_clipboard(f"Contraseña: {decrypted_password}")

        
    def copy_selected_entry(self):
        """Copia el usuario y la contraseña de la entrada seleccionada al portapapeles."""
        # Obtener la selección actual en el Listbox
        selected_index = self.password_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Copiar Selección", "No se ha seleccionado ningún elemento para copiar.")
            return

        # Obtener la entrada seleccionada
        entry_index = selected_index[0]
        entry = self.passwords[entry_index]

        # Extraer usuario y contraseña
        username = entry["username"]
        try:
            # Intentar desencriptar la contraseña, si es necesario
            decrypted_password = decrypt_password_with_rsa(bytes.fromhex(entry["password"]), private_key)
        except ValueError:
            decrypted_password = entry["password"]  # Usar contraseña en texto plano si no está encriptada

        # Formatear la cadena que se copiará (usuario y contraseña)
        text_to_copy = f"Usuario: {username}\nContraseña: {decrypted_password}"

        # Copiar la información al portapapeles
        self.copy_to_clipboard(text_to_copy)


    def copy_to_clipboard(self, text):
        """Copia el texto al portapapeles y lo limpia automáticamente después del tiempo configurado."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)  # Copia el texto al portapapeles
        messagebox.showinfo("Copiado", "El contenido se ha copiado al portapapeles.")
        # Limpiar el portapapeles después de un tiempo definido
        self.root.after(self.clipboard_timeout * 1000, self.clear_clipboard)

    def clear_clipboard(self):
        """Limpia el portapapeles y copia una cadena vacía para seguridad."""
        self.root.clipboard_clear()
        self.root.clipboard_append("")  # Copiar cadena vacía para asegurar limpieza
        messagebox.showinfo("Información", "Portapapeles limpiado automáticamente por seguridad.")

    def update_password_listbox(self, filtered_passwords=None):
        """Actualiza la lista de contraseñas mostrada en el Listbox. Puede recibir una lista filtrada."""
        self.setup_inactivity_timer()  # Reinicia el temporizador de inactividad
        self.password_listbox.delete(0, tk.END)  # Limpia la lista actual en el Listbox
        
        # Usa la lista completa si no se pasa una lista filtrada
        if filtered_passwords is None:
            filtered_passwords = self.passwords

        # Añade cada entrada de contraseña a la lista visual
        for entry in self.passwords:
            display_text = f"{entry['site_name']} ({entry['username']})"
            self.password_listbox.insert(tk.END, display_text)
        
        self.password_listbox.selection_clear(0, tk.END)  # Limpiar selección después de actualizar

    def add_entry(self):
        """Agrega una nueva entrada de contraseña con los datos actuales de los campos."""
        self.setup_inactivity_timer()
        current_time = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # Fecha y hora actuales
        encrypted_password = encrypt_password_with_rsa(self.password.get(), public_key)  # Cifrar contraseña
        
        # Crear nueva entrada con los datos de los campos
        entry = {
            "id": self.current_id,
            "site_name": self.site_name.get(),
            "username": self.username.get(),
            "password": encrypted_password.hex(),  # Guardar contraseña cifrada en hexadecimal
            "url": self.url.get(),
            "notes": self.notes.get(),
            "extra_fields": {
                "extra1": self.extra1.get(),
                "extra2": self.extra2.get(),
                "extra3": self.extra3.get(),
                "extra4": self.extra4.get(),
                "extra5": self.extra5.get()
            },
            "tags": self.tags.get().split(", "),  # Convierte etiquetas a lista
            "creation_date": current_time,
            "update_date": current_time,
            "expiration_date": f"{self.expiration_date.get()}T23:59:59Z",
            "icon": self.icon.get() if self.icon.get() else "default_icon.png"
        }
        self.passwords.append(entry)  # Añadir la entrada a la lista de contraseñas
        self.update_password_listbox()  # Actualizar el Listbox con la nueva entrada
        self.current_id += 1
        self.clear_fields()  # Limpiar los campos después de añadir

    def save_file(self):
        """Guarda todas las contraseñas en un archivo cifrado con DES."""
        # Construir lista de entradas en formato JSON
        entries = []
        for entry in self.passwords:
            # Convertir la contraseña cifrada a hexadecimal para guardar en el archivo
            encrypted_password_hex = entry["password"]

            # Crear formato JSON para cada entrada
            formatted_entry = {
                "id": entry["id"],
                "site_name": entry["site_name"],
                "username": entry["username"],
                "password": encrypted_password_hex,  # Almacena la contraseña en hexadecimal
                "url": entry["url"],
                "notes": entry["notes"],
                "extra_fields": {
                    "extra1": entry["extra_fields"]["extra1"],
                    "extra2": entry["extra_fields"]["extra2"],
                    "extra3": entry["extra_fields"]["extra3"],
                    "extra4": entry["extra_fields"]["extra4"],
                    "extra5": entry["extra_fields"]["extra5"]
                },
                "tags": entry["tags"],
                "creation_date": entry["creation_date"],
                "update_date": entry["update_date"],
                "expiration_date": entry["expiration_date"],
                "icon": entry["icon"]
            }
            entries.append(formatted_entry)

        # Crear estructura JSON principal
        json_data = {"entries": entries}

        # Serializar JSON y cifrar con DES usando la clave maestra
        try:
            json_str = json.dumps(json_data, indent=4)
            encrypted_data = encrypt_file(json_str, self.master_key)

            # Guardar el archivo cifrado
            file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted files", "*.enc")])
            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)
                messagebox.showinfo("Éxito", f"Archivo guardado en {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar el archivo: {e}")

    def load_file(self):
        """Carga un archivo cifrado con contraseñas y lo desencripta usando la clave maestra ingresada."""
        # Solicita al usuario seleccionar el archivo cifrado a cargar
        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if not file_path:
            return
        
        # Solicita la clave maestra para desencriptar el archivo
        entered_key = simpledialog.askstring("Clave Maestra", "Ingrese la clave maestra para desencriptar el archivo:", show="*")
        if not entered_key or len(entered_key) != 8:
            messagebox.showerror("Error", "Clave maestra inválida. Debe tener exactamente 8 caracteres.")
            return

        # Intenta desencriptar el archivo con la clave proporcionada
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            # Desencripta el contenido del archivo
            decrypted_data = decrypt_file(encrypted_data, entered_key)
            
            # Verifica si la desencriptación fue exitosa
            if decrypted_data:
                # Convierte el JSON desencriptado en una lista de contraseñas
                json_data = json.loads(decrypted_data)
                self.passwords = json_data.get("entries", [])  # Almacena las entradas en self.passwords
                self.update_password_listbox()
                messagebox.showinfo("Éxito", "Archivo cargado correctamente")
            else:
                messagebox.showerror("Error", "La clave maestra es incorrecta o el archivo no se pudo desencriptar.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar el archivo: {e}")

    def export_to_plain_text(self):
        """Exporta las contraseñas almacenadas en un archivo JSON en texto plano."""
        # Solicita una ubicación para guardar el archivo JSON
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not file_path:
            return

        try:
            # Crear un JSON con las contraseñas almacenadas
            json_data = {"entries": self.passwords}
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, ensure_ascii=False, indent=4)
            messagebox.showinfo("Exportación Exitosa", f"Contraseñas exportadas a {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar: {e}")

    def import_from_plain_text(self):
        """Importa contraseñas desde un archivo JSON o cifrado (enc)."""
        # Permite seleccionar archivos JSON y ENC
        file_path = filedialog.askopenfilename(filetypes=[("JSON or Encrypted files", "*.json *.enc")])
        if not file_path:
            return

        try:
            # Si el archivo es .enc, pide la clave maestra para desencriptarlo
            if file_path.endswith(".enc"):
                entered_key = simpledialog.askstring("Clave Maestra", "Ingrese la clave maestra para desencriptar el archivo:", show="*")
                if not entered_key or len(entered_key) != 8:
                    messagebox.showerror("Error", "Clave maestra inválida. Debe tener exactamente 8 caracteres.")
                    return

                # Lee y desencripta el archivo
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = decrypt_file(encrypted_data, entered_key)

                # Verifica la desencriptación
                if decrypted_data:
                    json_data = json.loads(decrypted_data)
                else:
                    messagebox.showerror("Error", "La clave maestra es incorrecta o el archivo no se pudo desencriptar.")
                    return
            else:
                # Si el archivo es JSON, lo carga directamente
                with open(file_path, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                    
            # Procesa y almacena las entradas del archivo importado
            entries = json_data.get("entries", [])
            self.passwords = []  # Limpia la lista actual de contraseñas
            
            # Carga cada entrada en la lista de contraseñas
            for entry in entries:
                try:
                    # Desencripta la contraseña si está en formato hexadecimal
                    if all(c in "0123456789abcdefABCDEF" for c in entry["password"]):
                        decrypted_password = decrypt_password_with_rsa(bytes.fromhex(entry["password"]), private_key)
                        entry["password"] = decrypted_password
                    else:
                        entry["password"] = entry["password"]  # Si no es hexadecimal, muestra el texto original
                except ValueError:
                    # Si no se puede desencriptar, usa la contraseña en su formato actual
                    entry["password"] = entry["password"]

                self.passwords.append(entry)

            # Muestra la primera entrada importada en los campos de la interfaz en texto plano
            if self.passwords:
                first_entry = self.passwords[0]
                self.site_name.set(first_entry["site_name"])
                self.username.set(first_entry["username"])
                self.password_entry.config(show="")  # Muestra la contraseña en texto plano
                self.password.set(first_entry["password"])
                self.url.set(first_entry["url"])
                self.notes.set(first_entry["notes"])
                self.extra1.set(first_entry["extra_fields"]["extra1"])
                self.extra2.set(first_entry["extra_fields"]["extra2"])
                self.extra3.set(first_entry["extra_fields"]["extra3"])
                self.extra4.set(first_entry["extra_fields"]["extra4"])
                self.extra5.set(first_entry["extra_fields"]["extra5"])
                self.tags.set(", ".join(first_entry["tags"]))
                self.icon.set(first_entry["icon"])
                self.expiration_date.set(first_entry["expiration_date"].split("T")[0])

            self.update_password_listbox()
            messagebox.showinfo("Importación Exitosa", "Contraseñas importadas correctamente y mostradas en texto plano.")

        except Exception as e:
            messagebox.showerror("Error", f"Error al importar: {e}")

    def update_password_listbox(self):
        """Actualiza el Listbox con todas las contraseñas almacenadas."""
        self.setup_inactivity_timer()  # Reinicia el temporizador de inactividad
        self.password_listbox.delete(0, tk.END)
        for entry in self.passwords:
            display_text = f"{entry['site_name']} ({entry['username']})"
            self.password_listbox.insert(tk.END, display_text)

    def clear_fields(self):
        """Limpia todos los campos de entrada en la interfaz."""
        self.site_name.set("")
        self.username.set("")
        self.password.set("")
        self.url.set("")
        self.notes.set("")
        self.extra1.set("")
        self.extra2.set("")
        self.extra3.set("")
        self.extra4.set("")
        self.extra5.set("")
        self.tags.set("")
        self.icon.set("")
        self.expiration_date.set("2025-12-31")  # Valor predeterminado para la fecha de vencimiento

# Ejecutar la aplicación
if __name__ == '__main__':
    root = tk.Tk()
    LoginWindow(root)  # Inicia la ventana de inicio de sesión
    root.mainloop()  # Inicia el bucle de eventos de la aplicación
