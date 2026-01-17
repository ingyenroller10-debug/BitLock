import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import json
import os
import base64
import string
import random
import csv
import time
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Theme settings ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class JelszoKezeloApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("BitLock - Modern Vault")
        self.geometry("1100x750")
        self.minsize(1000, 700)
        
        # Setting icon if file exists
        try:
            if os.path.exists("icon.ico"):
                self.iconbitmap("icon.ico")
        except:
            pass

        # Data management
        self.data_file = "bitlock_vault.dat"
        self.passwords = []
        self.fernet = None
        self.current_salt = None
        self.active_page = None

        # Icons and texts
        self.icons = {
            "vault": "🔒 Vault",
            "generator": "⚡ Generator",
            "add": "➕ New Entry",
            "settings": "⚙️ Settings",
            "logout": "🚪 Logout",
            "import": "📥 Import Chrome CSV"
        }

        if os.path.exists(self.data_file):
            self.show_login_screen()
        else:
            self.show_setup_screen()

    # --- CRYPTOGRAPHY ---
    def generate_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def load_vault(self, master_password):
        try:
            with open(self.data_file, "rb") as f:
                file_content = f.read()
            salt = file_content[:16]
            encrypted_data = file_content[16:]
            key = self.generate_key(master_password, salt)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            self.passwords = json.loads(decrypted_data.decode())
            self.fernet = fernet
            self.current_salt = salt
            return True
        except:
            return False

    def save_vault(self):
        if not self.fernet: return
        json_data = json.dumps(self.passwords).encode()
        encrypted_data = self.fernet.encrypt(json_data)
        with open(self.data_file, "wb") as f:
            f.write(self.current_salt + encrypted_data)

    # --- MACOS SMOOTH ANIMATIONS ---
    def smooth_transition(self, widget):
        """macOS style slide-in: bottom-to-top eased motion."""
        widget.update_idletasks()
        start_y = 0.53  # Starts slightly lower
        end_y = 0.5     # Target position
        
        steps = 25
        for i in range(steps + 1):
            # Easing function (Ease Out Quad)
            t = i / steps
            current_y = start_y - (start_y - end_y) * (t * (2 - t))
            widget.place_configure(relx=0.5, rely=current_y, anchor="center")
            
            self.update()
            time.sleep(0.008)

    # --- UI SCREENS ---
    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_window()
        frame = ctk.CTkFrame(self, width=400, height=450, corner_radius=25)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(frame, text="BitLock 🛡️", font=("SF Pro Display", 40, "bold"), text_color="#3B82F6").pack(pady=(50, 10))
        ctk.CTkLabel(frame, text="Welcome back!", font=("SF Pro Text", 16)).pack(pady=(0, 40))

        self.login_entry = ctk.CTkEntry(frame, placeholder_text="Master Password", show="*", width=300, height=50, corner_radius=15, border_width=0, fg_color="#2A2A2A")
        self.login_entry.pack(pady=10)
        self.login_entry.bind("<Return>", lambda e: self.perform_login())

        btn = ctk.CTkButton(frame, text="Unlock Vault", command=self.perform_login, width=300, height=50, corner_radius=15, font=("SF Pro Text", 16, "bold"), fg_color="#3B82F6", hover_color="#2563EB")
        btn.pack(pady=(30, 40))
        self.smooth_transition(frame)

    def show_setup_screen(self):
        self.clear_window()
        frame = ctk.CTkFrame(self, width=400, corner_radius=25)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(frame, text="Create Vault 🔐", font=("SF Pro Display", 32, "bold")).pack(pady=(40, 10))
        ctk.CTkLabel(frame, text="Set your master password", font=("SF Pro Text", 14), text_color="gray").pack(pady=(0, 20))
        
        self.setup_entry = ctk.CTkEntry(frame, placeholder_text="Master Password", show="*", width=300, height=45, corner_radius=12)
        self.setup_entry.pack(pady=10)
        self.setup_entry_confirm = ctk.CTkEntry(frame, placeholder_text="Confirm Password", show="*", width=300, height=45, corner_radius=12)
        self.setup_entry_confirm.pack(pady=10)

        ctk.CTkButton(frame, text="Initialize BitLock", command=self.perform_setup, width=300, height=50, corner_radius=15).pack(pady=(20, 40))
        self.smooth_transition(frame)

    def perform_login(self):
        if self.load_vault(self.login_entry.get()):
            self.launch_app_interface()
        else:
            self.login_entry.configure(border_width=2, border_color="#EF4444")
            self.after(1000, lambda: self.login_entry.configure(border_width=0))

    def perform_setup(self):
        pwd = self.setup_entry.get()
        if pwd and pwd == self.setup_entry_confirm.get():
            self.current_salt = os.urandom(16)
            self.fernet = Fernet(self.generate_key(pwd, self.current_salt))
            self.passwords = []
            self.save_vault()
            self.launch_app_interface()

    def launch_app_interface(self):
        self.clear_window()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar (Apple Style)
        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color="#18181B")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="BitLock", font=("SF Pro Display", 26, "bold"), text_color="#3B82F6").pack(pady=40, padx=20, anchor="w")

        self.nav_btns = []
        nav_items = [
            (self.icons["vault"], self.show_vault_page),
            (self.icons["generator"], self.show_generator_page),
            (self.icons["add"], self.show_add_page),
            (self.icons["settings"], self.show_settings_page)
        ]

        for i, (txt, cmd) in enumerate(nav_items):
            b = ctk.CTkButton(self.sidebar, text=txt, command=cmd, fg_color="transparent", height=45, anchor="w", corner_radius=10, font=("SF Pro Text", 14))
            b.pack(fill="x", padx=15, pady=4)
            self.nav_btns.append(b)

        ctk.CTkButton(self.sidebar, text=self.icons["logout"], command=self.logout, fg_color="transparent", text_color="#F87171", hover_color="#2D1A1A").pack(side="bottom", fill="x", padx=15, pady=30)

        self.content_container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_container.grid(row=0, column=1, sticky="nsew")
        
        self.show_vault_page()

    def switch_page(self, index):
        for i, btn in enumerate(self.nav_btns):
            btn.configure(fg_color="#3B82F6" if i == index else "transparent", 
                          text_color="white" if i == index else "#A1A1AA")
        
        for w in self.content_container.winfo_children():
            w.destroy()

    def logout(self):
        self.passwords = []
        self.fernet = None
        self.show_login_screen()

    # --- PAGES ---

    def show_vault_page(self):
        self.switch_page(0)
        page = ctk.CTkFrame(self.content_container, fg_color="transparent")
        page.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.9)

        header = ctk.CTkFrame(page, fg_color="transparent")
        header.pack(fill="x", pady=(0, 20))
        ctk.CTkLabel(header, text="Your Vault", font=("SF Pro Display", 32, "bold")).pack(side="left")

        self.search_entry = ctk.CTkEntry(header, placeholder_text="Search accounts...", width=250, height=35, corner_radius=10, border_width=0, fg_color="#27272A")
        self.search_entry.pack(side="right")
        self.search_entry.bind("<KeyRelease>", self.filter_passwords)

        self.scroll = ctk.CTkScrollableFrame(page, fg_color="transparent", label_text=f"Stored Passwords ({len(self.passwords)})")
        self.scroll.pack(fill="both", expand=True)

        self.display_passwords(self.passwords)
        self.smooth_transition(page)

    def show_generator_page(self):
        self.switch_page(1)
        page = ctk.CTkFrame(self.content_container, fg_color="transparent")
        page.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)

        ctk.CTkLabel(page, text="Password Generator", font=("SF Pro Display", 32, "bold")).pack(anchor="w", pady=(0, 30))

        panel = ctk.CTkFrame(page, corner_radius=20, fg_color="#18181B", border_width=1, border_color="#27272A")
        panel.pack(fill="x", padx=5, pady=5, ipady=20)

        self.len_var = tk.IntVar(value=16)
        l_frame = ctk.CTkFrame(panel, fg_color="transparent")
        l_frame.pack(fill="x", padx=30, pady=20)
        self.l_label = ctk.CTkLabel(l_frame, text=f"Length: {self.len_var.get()}", font=("SF Pro Text", 16, "bold"))
        self.l_label.pack(side="left")
        ctk.CTkSlider(l_frame, from_=8, to=40, variable=self.len_var, command=lambda v: self.l_label.configure(text=f"Length: {int(v)}")).pack(side="right", fill="x", expand=True, padx=(20, 0))

        self.res_entry = ctk.CTkEntry(page, font=("JetBrains Mono", 24), height=70, justify="center", corner_radius=15, border_width=0, fg_color="#27272A")
        self.res_entry.pack(fill="x", pady=30)

        btn_f = ctk.CTkFrame(page, fg_color="transparent")
        btn_f.pack(fill="x")
        ctk.CTkButton(btn_f, text="Generate", height=55, command=self.gen_pwd, font=("SF Pro Text", 16, "bold")).pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(btn_f, text="Copy", height=55, width=150, fg_color="#3F3F46", command=self.copy_gen).pack(side="right")

        self.smooth_transition(page)

    def show_add_page(self):
        self.switch_page(2)
        page = ctk.CTkFrame(self.content_container, fg_color="transparent")
        page.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)

        ctk.CTkLabel(page, text="Add New Entry", font=("SF Pro Display", 32, "bold")).pack(anchor="w", pady=(0, 40))

        self.e_name = self.create_input(page, "Service Name (e.g. Netflix)")
        self.e_user = self.create_input(page, "Email / Username")
        self.e_pass = self.create_input(page, "Password", secret=True)

        ctk.CTkButton(page, text="Save to Vault", height=55, width=250, command=self.save_entry, corner_radius=15, font=("SF Pro Text", 16, "bold")).pack(pady=40, anchor="w")
        self.smooth_transition(page)

    def create_input(self, master, label, secret=False):
        ctk.CTkLabel(master, text=label, font=("SF Pro Text", 13), text_color="#A1A1AA").pack(anchor="w", padx=5, pady=(10, 0))
        e = ctk.CTkEntry(master, width=500, height=45, corner_radius=10, border_width=0, fg_color="#18181B", show="*" if secret else "")
        e.pack(anchor="w", pady=(5, 10))
        return e

    def show_settings_page(self):
        self.switch_page(3)
        page = ctk.CTkFrame(self.content_container, fg_color="transparent")
        page.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.8, relheight=0.8)
        
        ctk.CTkLabel(page, text="Settings", font=("SF Pro Display", 32, "bold")).pack(pady=(0, 40), anchor="w")
        
        panel = ctk.CTkFrame(page, corner_radius=20, fg_color="#18181B", border_width=1, border_color="#27272A")
        panel.pack(fill="x", pady=10, ipady=20)
        
        ctk.CTkLabel(panel, text="Data Import", font=("SF Pro Text", 18, "bold")).pack(pady=(20, 5), padx=30, anchor="w")
        ctk.CTkLabel(panel, text="Load your passwords exported from Chrome (.csv)", font=("SF Pro Text", 14), text_color="gray").pack(padx=30, anchor="w")
        
        ctk.CTkButton(panel, text=self.icons["import"], command=self.import_chrome_csv, height=45, fg_color="#3B82F6", corner_radius=12).pack(pady=30, padx=30, anchor="w")

        self.smooth_transition(page)

    # --- FUNCTIONALITY ---
    def import_chrome_csv(self):
        f_path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not f_path: return
        try:
            count = 0
            with open(f_path, mode='r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = row.get('name') or row.get('url') or "Unknown"
                    user = row.get('username') or ""
                    pwd = row.get('password') or ""
                    if name and pwd:
                        self.passwords.append({"name": name, "username": user, "password": pwd})
                        count += 1
            if count > 0:
                self.save_vault()
                messagebox.showinfo("Success", f"{count} entries successfully imported!")
                self.show_vault_page()
        except Exception as e:
            messagebox.showerror("Error", f"Import failed: {str(e)}")

    def gen_pwd(self):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        res = "".join(random.choice(chars) for _ in range(self.len_var.get()))
        self.res_entry.delete(0, tk.END)
        self.res_entry.insert(0, res)

    def copy_gen(self):
        self.clipboard_clear()
        self.clipboard_append(self.res_entry.get())
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def save_entry(self):
        n, u, p = self.e_name.get(), self.e_user.get(), self.e_pass.get()
        if n and p:
            self.passwords.append({"name": n, "username": u, "password": p})
            self.save_vault()
            self.show_vault_page()

    def display_passwords(self, data):
        # Clear existing items in scroll frame
        for w in self.scroll.winfo_children():
            w.destroy()
            
        # Update label with result count
        self.scroll.configure(label_text=f"Stored Passwords ({len(data)})")
        
        for item in data:
            card = ctk.CTkFrame(self.scroll, fg_color="#18181B", height=85, corner_radius=15, border_width=1, border_color="#27272A")
            card.pack(fill="x", pady=6, padx=10)
            card.pack_propagate(False)
            
            ic = ctk.CTkFrame(card, width=45, height=45, corner_radius=12, fg_color="#3B82F6")
            ic.pack(side="left", padx=15)
            ctk.CTkLabel(ic, text=item['name'][0].upper() if item['name'] else "?", font=("SF Pro Display", 20, "bold")).place(relx=0.5, rely=0.5, anchor="center")

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", fill="both", expand=True, pady=15)
            ctk.CTkLabel(info, text=item['name'], font=("SF Pro Text", 16, "bold"), anchor="w").pack(fill="x")
            ctk.CTkLabel(info, text=item['username'] or "No username", font=("SF Pro Text", 12), text_color="gray", anchor="w").pack(fill="x")
            
            ctk.CTkButton(card, text="Copy", width=80, height=32, corner_radius=8, command=lambda p=item['password']: self.copy_p(p)).pack(side="right", padx=15)
            ctk.CTkButton(card, text="🗑️", width=35, height=35, fg_color="transparent", text_color="#F87171", command=lambda n=item['name']: self.del_e(n)).pack(side="right")

    def copy_p(self, p):
        self.clipboard_clear()
        self.clipboard_append(p)
        # Briefly change button state or show toast would be better, but keep it simple
        self.update()

    def del_e(self, n):
        if messagebox.askyesno("Delete", "Are you sure you want to delete this entry?"):
            self.passwords = [x for x in self.passwords if x['name'] != n]
            self.save_vault()
            self.show_vault_page()

    def filter_passwords(self, event=None):
        query = self.search_entry.get().lower()
        if not query:
            filtered = self.passwords
        else:
            filtered = [
                x for x in self.passwords 
                if query in x['name'].lower() or query in (x['username'] or "").lower()
            ]
        self.display_passwords(filtered)

if __name__ == "__main__":
    app = JelszoKezeloApp()
    app.mainloop()