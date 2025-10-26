import os
import ast
import sys
import bcrypt
import json
import customtkinter as ctk # type: ignore
from tkinter import messagebox
from tkinter import font
from cryptography.fernet import Fernet
import base64
import hashlib


root = ctk.CTk()
root.title("Valtigo")
root.after(201, lambda :root.iconbitmap('C:\Code Bank\python bank\icon.ico'))
root.configure(corner_radius=20)
ctk.set_appearance_mode("dark")

goodpass = ctk.CTkToplevel(root)
goodpass.title("Valtigo")
goodpass.geometry("500x400")
goodpass.iconbitmap("icon.ico")


setpwrd = ctk.CTkToplevel(root)
setpwrd.title("Valtigo")
setpwrd.geometry("500x400")
setpwrd.iconbitmap("icon.ico")


youshalnotpass = ctk.CTkToplevel(root)
youshalnotpass.title("You Shall Not Pass!")
youshalnotpass.geometry("500x400")
youshalnotpass.iconbitmap("icon.ico")


loginaddgui = ctk.CTkToplevel(root)
loginaddgui.title("Login Saver")
loginaddgui.geometry("500x400")
loginaddgui.iconbitmap("icon.ico")


pwordlist = ctk.CTkToplevel(root)
pwordlist.title("Saved Passwords")
pwordlist.geometry("500x400")
pwordlist.iconbitmap("icon.ico")


goodpass.withdraw()
setpwrd.withdraw()
youshalnotpass.withdraw()
loginaddgui.withdraw()
pwordlist.withdraw()

window_width = 500
window_height = 400

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)

root.geometry(f"{window_width}x{window_height}+{x}+{y}")

font_one = ctk.CTkFont(family="Arial", size=12, weight="bold")

placeholder = "--"
master_password = None

themes = ["Rose", "Pink", "Breeze", "Sky", "Marsh", "Cherry", "Violet", "Red"]

documents_folder = os.path.join(os.path.expanduser("~"), "Documents")

valtigo_folder = os.path.join(documents_folder, "Valtigo")
os.makedirs(valtigo_folder, exist_ok=True)

ecrpt = os.path.join(valtigo_folder, "ecrypt.valtigo")
nigol = os.path.join(valtigo_folder, "users.valtigo")
KEYFILE = os.path.join(valtigo_folder, "key.key")

config_path = "assets\config.txt"

with open(config_path, "r") as file:
    theme_config_choice = file.read()
ctk.set_default_color_theme(f"{theme_config_choice}")

def check_password():
    entered = login_password_entry.get()

    if not os.path.exists(ecrpt):
        messagebox.showerror("Error", "No password has been set yet!")
        return

    with open(ecrpt, "rb") as file:
        stored_hash = file.read()

    if bcrypt.checkpw(entered.encode('utf-8'), stored_hash):
        passconfirmed()
    else:
        passdenied()

def reset():
    login_password_entry.delete(0, ctk.END)

def ext():
    root.destroy()  

def logout():
    root.deiconify()

def closegoodpass():
        goodpass.withdraw()
        logout()

def update_slider_value(value):
    global slider_value
    slider_value = float(value)

def apply_scale(value):    
    scale = slider_value / 50
    new_width = int(window_width * scale)
    new_height = int(window_height * scale)
    new_x = (screen_width // 2) - (new_width // 2)
    new_y = (screen_height // 2) - (new_height // 2)

    root.geometry(f"{new_width}x{new_height}+{new_x}+{new_y}")
    if float(value) == 50:
        ext()

def passconfirmed():
    global master_password
    master_password = login_password_entry.get().strip()
    root.withdraw()
    goodpass.deiconify()

def passdenied():
    passdenied = ctk.CTkToplevel(root)
    passdenied.iconbitmap(r"C:\Code Bank\python bank\icon.ico")
    passdenied.geometry("300x200")
    passdenied.title("Access Denied!")
    passdenied_label = ctk.CTkLabel(passdenied, text="Access denied! Try again bud!")
    passdenied_label.pack(pady=5)

def setpwordgui():
    setpwrd.deiconify()

def setpass():
    pw = entry.get().strip()

    if not pw:
        messagebox.showwarning("Error", "Password cannot be empty.")
        return

    hashed = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())

    with open(ecrpt, "wb") as file:
        file.write(hashed)

    try:
        os.chmod(ecrpt, 0o600)
    except Exception:
        pass

def pwordalreadyset():
    youshalnotpass.deiconify()

def closealreadyset():
    youshalnotpass.withdraw()

def pwrdcheck():
    if not os.path.exists(ecrpt):
        setpass()
    else:
        pwordalreadyset()

def rebuild_widgets():
    global login_password_entry, submit_btn, clear_btn, exit_btn
    for widget in right_frame.winfo_children():
        widget.destroy()

    ctk.CTkLabel(right_frame, text="CatMan's Demonstration Vault! \n Enter Password:", font=font_one).pack(pady=10)
    login_password_entry = ctk.CTkEntry(right_frame, show="*")
    login_password_entry.pack(pady=5)

    submit_btn = ctk.CTkButton(right_frame, text="Submit", command=check_password, corner_radius=100)
    submit_btn.pack(pady=5)

    clear_btn = ctk.CTkButton(right_frame, text="Clear", command=reset, corner_radius=100)
    clear_btn.pack(pady=5)

    exit_btn = ctk.CTkButton(right_frame, text="Exit", command=ext, corner_radius=100)
    exit_btn.pack(pady=5)

def addentry():
    loginaddgui.deiconify()

def theme_picker(choice):
    if choice == "Rose":
        pass
    elif choice == "Pink":
        pass
    elif choice == "Sky":
        pass
    elif choice == "Breeze":
        pass
    elif choice == "Marsh":
        pass
    elif choice == "Cherry":
        pass
    elif choice == "Violet":
        pass
    elif choice == "Red":
        pass
    with open("assets\config.txt","w") as file:
        file.write(f"assets\{choice}.json")
    rebuild_widgets()
    theme_picket_confirm = ctk.CTkToplevel(root)
    theme_picket_confirm.iconbitmap(r"C:\Code Bank\python bank\icon.ico")
    theme_picket_confirm.geometry("300x200")
    theme_picket_confirm.title("Success!")
    theme_picket_confirm_label = ctk.CTkLabel(theme_picket_confirm, text="Choice saved and will be applied on next startup!")
    theme_picket_confirm_label.pack(pady=5)

def load_users():
    if os.path.exists(nigol) and os.path.getsize(nigol) > 0:
        with open(nigol, "r") as f:
            return json.load(f)
    return {}

def save_user(name, username, password):
    name = name.strip()
    username = username.strip()
    password = password.strip()

    if not name or not username or not password:
        messagebox.showwarning("Error", "All fields must be filled.")
        return False

    users = load_users()
    if name in users:
        messagebox.showwarning("Error", f"An entry named '{name}' already exists!")
        return False

    encrypted_pw = encrypt_with_keyfile(password)
    users[name] = {
        "username": username,
        "password": encrypted_pw
    }

    with open(nigol, "w") as f:
        json.dump(users, f, indent=4)

    messagebox.showinfo("Success", f"Saved '{name}' successfully!")
    return True


def check_user(username, password):
    users = load_users()

    if username not in users:
        messagebox.showerror("Error", "Username does not exist!")
        return False

    hashed = users[username].encode("utf-8")
    if bcrypt.checkpw(password.encode("utf-8"), hashed):
        messagebox.showinfo("Success", f"Welcome, {username}!")
        return True
    else:
        messagebox.showerror("Error", "Incorrect password!")
        return False


def get_or_create_keyfile():
    if os.path.exists(KEYFILE):
        with open(KEYFILE, "rb") as kf:
            return kf.read()
    key = Fernet.generate_key()
    with open(KEYFILE, "wb") as kf:
        kf.write(key)
    try:
        os.chmod(KEYFILE, 0o600)
    except Exception:
        pass
    return key

def encrypt_with_keyfile(plain_password: str) -> str:
    key = get_or_create_keyfile()
    f = Fernet(key)
    return f.encrypt(plain_password.encode()).decode()

def decrypt_with_keyfile(encrypted_password: str) -> str:
    key = get_or_create_keyfile()
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

def openpsswordmanagr():
    pwordlist.deiconify()
    pwordlist.title("Saved Passwords")

    ctk.CTkLabel(pwordlist, text="Saved Accounts", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)

    scroll_frame = ctk.CTkScrollableFrame(pwordlist, width=460, height=340)
    scroll_frame.pack(padx=10, pady=10, fill="both", expand=True)

    users = load_users()
    if not users:
        ctk.CTkLabel(scroll_frame, text="No saved accounts.", font=ctk.CTkFont(size=12)).pack(pady=5)
        return

    for name, data in users.items():
        if not isinstance(data, dict):
            continue
        try:
            decrypted_pw = decrypt_with_keyfile(data["password"])
        except Exception:
            decrypted_pw = "<Failed to decrypt>"

        ctk.CTkLabel(scroll_frame, text=f"Name: {name}", anchor="w", font=ctk.CTkFont(size=12, weight="bold")).pack(fill="x", padx=5, pady=(5,0))
        ctk.CTkLabel(scroll_frame, text=f"Username: {data.get('username','')}", anchor="w", font=ctk.CTkFont(size=12)).pack(fill="x", padx=5)
        ctk.CTkLabel(scroll_frame, text=f"Password: {decrypted_pw}", anchor="w", font=ctk.CTkFont(size=12)).pack(fill="x", padx=5, pady=(0,5))


left_frame = ctk.CTkFrame(root)
left_frame.pack(side="left", fill="y", padx=5, pady=5)

right_frame = ctk.CTkFrame(root)
right_frame.pack(side="right", expand=True, fill="both", padx=5, pady=5)

ctk.CTkLabel(right_frame, text="CatMan's Demonstration Vault! \n Enter Password:", font=font_one).pack(pady=10)
login_password_entry = ctk.CTkEntry(right_frame, show="*")
login_password_entry.pack(pady=5)

scale_slider = ctk.CTkSlider(left_frame, from_=20, to=100, number_of_steps=100, command=update_slider_value, orientation="vertical")
scale_slider.set(0)
scale_slider.pack(expand=True, fill="y")
scale_slider.bind("<ButtonRelease-1>", apply_scale)

submit_btn = ctk.CTkButton(right_frame, text="Submit", command=check_password, corner_radius=100)
submit_btn.pack(pady=5)

clear_btn = ctk.CTkButton(right_frame, text="Clear", command=reset, corner_radius=100)
clear_btn.pack(pady=5)

set_password = ctk.CTkButton(right_frame, text="Set Password", command=setpwordgui, corner_radius=100)
set_password.pack(pady=5)

exit_btn = ctk.CTkButton(right_frame, text="Exit", command=ext, corner_radius=100)
exit_btn.pack(pady=5)

themes_option_menu = ctk.StringVar(value="Light")
themes_option_menu = ctk.CTkOptionMenu(left_frame, values=themes, command=theme_picker, )
themes_option_menu_label = ctk.CTkLabel(left_frame, text="Coming Soon | Theme selector")
themes_option_menu.pack(pady=5)

## ---------------------------------------
## ___________Set Password Code___________

entry = ctk.CTkEntry(setpwrd, placeholder_text="Set a password")
entry.pack(pady=10)

submit = ctk.CTkButton(setpwrd, text="Submit", command=pwrdcheck)
submit.pack(pady=30)

## ---------------------------------------
## ___________Main Manager Code___________

left_frame_2 = ctk.CTkFrame(goodpass)
left_frame_2.pack(side="left", fill="y", padx=5, pady=5)

right_frame_2 = ctk.CTkFrame(goodpass)
right_frame_2.pack(side="right", expand=True, fill="both", padx=5, pady=5)

open_password_manager_gui_btn = ctk.CTkButton( right_frame_2,  text="Open Password List",  command=openpsswordmanagr,  corner_radius=100 )
open_password_manager_gui_btn.pack(pady=10)

themes_option_menu = ctk.StringVar(goodpass, value="Light")
themes_option_menu = ctk.CTkOptionMenu(left_frame_2, values=themes, command=theme_picker, )
themes_option_menu_label = ctk.CTkLabel(left_frame_2, text="Coming Soon | Theme selector")
themes_option_menu.pack(pady=20)

logout_btn = ctk.CTkButton(left_frame_2, text="Logout", command=closegoodpass, corner_radius=100)
logout_btn.pack(pady=20)

creat_login_button = ctk.CTkButton(left_frame_2, text="Add Login", command=addentry)
creat_login_button.pack(pady=15)

## ---------------------------------------
## ____________Login Saver Code!___________

ctk.CTkLabel(loginaddgui, text="Name").pack(pady=5)
name_entry = ctk.CTkEntry(loginaddgui)
name_entry.pack(pady=5)

ctk.CTkLabel(loginaddgui, text="Username").pack(pady=5)
username_entry = ctk.CTkEntry(loginaddgui)
username_entry.pack(pady=5)

ctk.CTkLabel(loginaddgui, text="Password").pack(pady=5)
password_entry = ctk.CTkEntry(loginaddgui, show="*")
password_entry.pack(pady=5)

def register():
    save_user(name_entry.get(), username_entry.get(), password_entry.get())

ctk.CTkButton(loginaddgui, text="Register", command=register).pack(pady=10)
ctk.CTkButton(loginaddgui, text="Open Password List", command=openpsswordmanagr).pack(pady=10)

def login():
    check_user(username_entry.get(), password_entry.get())

ctk.CTkButton(loginaddgui, text="Register", command=register).pack(pady=10)
ctk.CTkButton(loginaddgui, text="Login", command=login).pack(pady=10)

root.mainloop()
