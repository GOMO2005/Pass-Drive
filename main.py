import os
import json
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
from getpass import getpass

# Function to generate and save a key
def generate_key():
    return Fernet.generate_key()

# Function to save the key to a file
def save_key(key, file_path):
    with open(file_path, "wb") as key_file:
        key_file.write(key)

# Function to load the key from a file
def load_key(file_path):
    with open(file_path, "rb") as key_file:
        return key_file.read()

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

# Function to store login data on a USB drive
def store_login_data(usb_path, username, password, key):
    login_data = {
        'username': encrypt_data(username, key),
        'password': encrypt_data(password, key)
    }
    
    file_path = os.path.join(usb_path, "login_data.json")
    
    with open(file_path, "w") as file:
        json.dump(login_data, file)

# Function to retrieve login data from USB drive
def retrieve_login_data(usb_path, key):
    file_path = os.path.join(usb_path, "login_data.json")
    
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "No login data found.")
        return None
    
    with open(file_path, "r") as file:
        login_data = json.load(file)
    
    username = decrypt_data(login_data['username'], key)
    password = decrypt_data(login_data['password'], key)
    
    return username, password

# GUI for storing and retrieving login data
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Password Manager")
        self.root.geometry("400x400")
        
        self.key = None
        self.key_path = "encryption.key"
        
        # Add Buttons and Fields for actions
        self.create_widgets()

    def create_widgets(self):
        # USB path input
        self.usb_path_label = tk.Label(self.root, text="USB Drive Path:")
        self.usb_path_label.pack(pady=5)

        self.usb_path_entry = tk.Entry(self.root, width=40)
        self.usb_path_entry.pack(pady=5)
        
        # Buttons for storing and retrieving data
        self.store_button = tk.Button(self.root, text="Store Login Data", command=self.store_login_data)
        self.store_button.pack(pady=10)

        self.retrieve_button = tk.Button(self.root, text="Retrieve Login Data", command=self.retrieve_login_data)
        self.retrieve_button.pack(pady=10)

        # Username and password input fields
        self.username_label = tk.Label(self.root, text="Username:")
        self.username_label.pack(pady=5)

        self.username_entry = tk.Entry(self.root, width=40)
        self.username_entry.pack(pady=5)

        self.password_label = tk.Label(self.root, text="Password (up to 2000 characters):")
        self.password_label.pack(pady=5)

        self.password_entry = tk.Entry(self.root, width=40)
        self.password_entry.pack(pady=5)

        self.load_key()

    def load_key(self):
        if os.path.exists(self.key_path):
            self.key = load_key(self.key_path)
        else:
            self.key = generate_key()
            save_key(self.key, self.key_path)

    def store_login_data(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Check password length
        if len(password) > 2000:
            messagebox.showerror("Error", "Password cannot be longer than 2000 characters.")
            return

        usb_path = self.usb_path_entry.get().strip()
        if not os.path.exists(usb_path):
            messagebox.showerror("Error", "USB path does not exist.")
            return

        store_login_data(usb_path, username, password, self.key)
        messagebox.showinfo("Success", "Login data has been securely stored on the USB drive.")

    def retrieve_login_data(self):
        usb_path = self.usb_path_entry.get().strip()
        if not os.path.exists(usb_path):
            messagebox.showerror("Error", "USB path does not exist.")
            return

        credentials = retrieve_login_data(usb_path, self.key)
        if credentials:
            username, password = credentials
            messagebox.showinfo("Login Data", f"Username: {username}\nPassword: {password}")

# Create the main window and start the app
def run_app():
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_app()
