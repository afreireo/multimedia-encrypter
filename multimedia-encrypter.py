
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Clase para manejar operaciones de cifrado y descifrado
class FileEncryptor:
    def __init__(self, password):
        self.password = password.encode()
        self.key = self.generate_key_from_password()

    def generate_key_from_password(self):
        # Generar un hash SHA-256 de la contraseña como clave de cifrado
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.password)
        return digest.finalize()

    def encrypt_file(self, input_file, output_file):
        iv = os.urandom(16)  # Vector de inicialización aleatorio
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Leer y cifrar el contenido del archivo
        with open(input_file, 'rb') as f:
            data = f.read()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Guardar el archivo cifrado con iv
        with open(output_file, 'wb') as f:
            f.write(iv + encrypted_data)

    def decrypt_file(self, input_file, output_file):
        with open(input_file, 'rb') as f:
            iv = f.read(16)  # Leer el iv
            encrypted_data = f.read()

        # Crear descifrador y descifrar el contenido
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Guardar el archivo descifrado
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)

# Clase para la interfaz de usuario
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Multimedia Encrypter")  # Título de la ventana

        # Crear carpetas si no existen
        self.encrypted_folder = "Archivos encriptados"
        self.decrypted_folder = "Archivos desencriptados"
        os.makedirs(self.encrypted_folder, exist_ok=True)
        os.makedirs(self.decrypted_folder, exist_ok=True)

        # Configurar la interfaz de usuario
        self.encrypt_button = tk.Button(root, text="Cifrar", command=self.encrypt_file)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Descifrar", command=self.decrypt_file)
        self.decrypt_button.pack(pady=10)

    def encrypt_file(self):
        input_file = filedialog.askopenfilename(title="Seleccione el archivo para cifrar")
        if input_file:
            password = self.ask_for_password("Cifrar archivo")
            if password:
                password_encryptor = FileEncryptor(password)
                output_file = os.path.join(self.encrypted_folder, os.path.basename(input_file))
                try:
                    password_encryptor.encrypt_file(input_file, output_file)
                    messagebox.showinfo("Éxito", f"Archivo cifrado exitosamente y guardado en {output_file}")
                except Exception as e:
                    messagebox.showerror("Error", f"Error al cifrar el archivo: {e}")

    def decrypt_file(self):
        input_file = filedialog.askopenfilename(initialdir=self.encrypted_folder, title="Seleccione el archivo para descifrar")
        if input_file:
            password = self.ask_for_password("Descifrar archivo")
            if password:
                password_encryptor = FileEncryptor(password)
                output_file = os.path.join(self.decrypted_folder, os.path.basename(input_file))
                try:
                    password_encryptor.decrypt_file(input_file, output_file)
                    messagebox.showinfo("Éxito", f"Archivo descifrado exitosamente y guardado en {output_file}")
                except Exception as e:
                    messagebox.showerror("Error", f"Error al descifrar el archivo: {e}")

    def ask_for_password(self, action):
        password = simpledialog.askstring("Contraseña", f"Ingrese la contraseña para {action}:")
        if not password:
            messagebox.showerror("Error", "Debe ingresar una contraseña.")
        return password

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
