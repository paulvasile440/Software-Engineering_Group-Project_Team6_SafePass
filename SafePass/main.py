import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox

from database import Database
from security import (
    create_verifier,
    decrypt_text,
    derive_key,
    encrypt_text,
    generate_salt,
    verify_master_password,
)


APP_TITLE = "SafePass - Desktop Password Manager"


class SafePassApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("820x520")
        self.minsize(760, 480)

        self.db = Database()
        self.encryption_key = None
        self.current_frame = None

        self.show_login_screen()

    def clear_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()
        self.current_frame = ttk.Frame(self, padding=24)
        self.current_frame.pack(fill="both", expand=True)

    def show_login_screen(self):
        self.encryption_key = None
        self.clear_frame()

        panel = ttk.Frame(self.current_frame, padding=28)
        panel.place(relx=0.5, rely=0.45, anchor="center")

        ttk.Label(panel, text="SafePass", font=("Segoe UI", 24, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 8)
        )

        if not self.db.has_master_password():
            ttk.Label(
                panel,
                text="First time setup: create your master password.",
            ).grid(row=1, column=0, columnspan=2, pady=(0, 18))

            ttk.Label(panel, text="Master password:").grid(row=2, column=0, sticky="w", pady=6)
            password_entry = ttk.Entry(panel, show="*", width=32)
            password_entry.grid(row=2, column=1, pady=6)

            ttk.Label(panel, text="Confirm password:").grid(row=3, column=0, sticky="w", pady=6)
            confirm_entry = ttk.Entry(panel, show="*", width=32)
            confirm_entry.grid(row=3, column=1, pady=6)

            def setup():
                password = password_entry.get()
                confirm = confirm_entry.get()

                if len(password) < 8:
                    messagebox.showerror("SafePass", "Use at least 8 characters for the master password.")
                    return
                if password != confirm:
                    messagebox.showerror("SafePass", "The two passwords do not match.")
                    return

                salt = generate_salt()
                verifier = create_verifier(password, salt)
                self.db.set_setting("master_salt", salt)
                self.db.set_setting("master_verifier", verifier)
                self.encryption_key = derive_key(password, salt)
                self.show_vault()

            ttk.Button(panel, text="Create SafePass Vault", command=setup).grid(
                row=4, column=0, columnspan=2, pady=(18, 0), sticky="ew"
            )
            password_entry.focus_set()
        else:
            ttk.Label(panel, text="Enter your master password.").grid(
                row=1, column=0, columnspan=2, pady=(0, 18)
            )
            ttk.Label(panel, text="Master password:").grid(row=2, column=0, sticky="w", pady=6)
            password_entry = ttk.Entry(panel, show="*", width=32)
            password_entry.grid(row=2, column=1, pady=6)

            def login(event=None):
                password = password_entry.get()
                salt = self.db.get_setting("master_salt")
                verifier = self.db.get_setting("master_verifier")

                if verify_master_password(password, salt, verifier):
                    self.encryption_key = derive_key(password, salt)
                    self.show_vault()
                else:
                    messagebox.showerror("SafePass", "Incorrect master password.")
                    password_entry.delete(0, tk.END)
                    password_entry.focus_set()

            ttk.Button(panel, text="Login", command=login).grid(
                row=3, column=0, columnspan=2, pady=(18, 0), sticky="ew"
            )
            password_entry.bind("<Return>", login)
            password_entry.focus_set()

    def show_vault(self):
        self.clear_frame()

        header = ttk.Frame(self.current_frame)
        header.pack(fill="x", pady=(0, 15))

        ttk.Label(header, text="Password Vault", font=("Segoe UI", 20, "bold")).pack(side="left")
        ttk.Button(header, text="Logout", command=self.show_login_screen).pack(side="right")

        toolbar = ttk.Frame(self.current_frame)
        toolbar.pack(fill="x", pady=(0, 10))

        ttk.Button(toolbar, text="Add", command=self.add_record_dialog).pack(side="left", padx=(0, 6))
        ttk.Button(toolbar, text="Edit", command=self.edit_selected).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Delete", command=self.delete_selected).pack(side="left", padx=6)
        ttk.Button(toolbar, text="View Password", command=self.view_selected_password).pack(side="left", padx=6)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_records).pack(side="left", padx=6)

        columns = ("service", "username", "password", "updated")
        self.tree = ttk.Treeview(self.current_frame, columns=columns, show="headings", height=16)
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")
        self.tree.heading("updated", text="Updated")

        self.tree.column("service", width=220)
        self.tree.column("username", width=220)
        self.tree.column("password", width=120, anchor="center")
        self.tree.column("updated", width=160)

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda _event: self.edit_selected())

        ttk.Label(
            self.current_frame,
            text="Passwords are hidden by default. Use 'View Password' to reveal a selected password.",
        ).pack(anchor="w", pady=(10, 0))

        self.refresh_records()

    def refresh_records(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for row in self.db.list_records():
            self.tree.insert(
                "",
                "end",
                iid=str(row["id"]),
                values=(row["service"], row["username"], "••••••••", row["updated_at"]),
            )

    def selected_record_id(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("SafePass", "Please select a record first.")
            return None
        return int(selection[0])

    def add_record_dialog(self):
        self.record_dialog()

    def edit_selected(self):
        record_id = self.selected_record_id()
        if record_id is None:
            return

        row = self.db.get_record(record_id)
        try:
            password = decrypt_text(row["password_encrypted"], self.encryption_key)
            notes = decrypt_text(row["notes_encrypted"], self.encryption_key) if row["notes_encrypted"] else ""
        except ValueError:
            messagebox.showerror("SafePass", "Unable to decrypt this record.")
            return

        self.record_dialog(
            record_id=record_id,
            service=row["service"],
            username=row["username"],
            password=password,
            notes=notes,
        )

    def delete_selected(self):
        record_id = self.selected_record_id()
        if record_id is None:
            return

        if messagebox.askyesno("SafePass", "Delete the selected password record?"):
            self.db.delete_record(record_id)
            self.refresh_records()

    def view_selected_password(self):
        record_id = self.selected_record_id()
        if record_id is None:
            return

        row = self.db.get_record(record_id)
        try:
            password = decrypt_text(row["password_encrypted"], self.encryption_key)
        except ValueError:
            messagebox.showerror("SafePass", "Unable to decrypt this password.")
            return

        popup = tk.Toplevel(self)
        popup.title("View Password")
        popup.resizable(False, False)
        popup.grab_set()

        frame = ttk.Frame(popup, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text=f"Service: {row['service']}").pack(anchor="w", pady=4)
        ttk.Label(frame, text=f"Username: {row['username']}").pack(anchor="w", pady=4)

        password_var = tk.StringVar(value=password)
        ttk.Entry(frame, textvariable=password_var, width=40, state="readonly").pack(fill="x", pady=8)

        def copy_password():
            self.clipboard_clear()
            self.clipboard_append(password)
            self.update()
            messagebox.showinfo("SafePass", "Password copied to clipboard.")

        ttk.Button(frame, text="Copy Password", command=copy_password).pack(side="left", padx=(0, 8))
        ttk.Button(frame, text="Close", command=popup.destroy).pack(side="right")

    def generate_password(self, target_entry):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        password = "".join(secrets.choice(alphabet) for _ in range(16))
        target_entry.delete(0, tk.END)
        target_entry.insert(0, password)

    def record_dialog(self, record_id=None, service="", username="", password="", notes=""):
        popup = tk.Toplevel(self)
        popup.title("Edit Password Record" if record_id else "Add Password Record")
        popup.geometry("470x390")
        popup.resizable(False, False)
        popup.grab_set()

        frame = ttk.Frame(popup, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Service / Website:").grid(row=0, column=0, sticky="w", pady=7)
        service_entry = ttk.Entry(frame, width=36)
        service_entry.grid(row=0, column=1, sticky="ew", pady=7)
        service_entry.insert(0, service)

        ttk.Label(frame, text="Username / Email:").grid(row=1, column=0, sticky="w", pady=7)
        username_entry = ttk.Entry(frame, width=36)
        username_entry.grid(row=1, column=1, sticky="ew", pady=7)
        username_entry.insert(0, username)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="w", pady=7)
        password_entry = ttk.Entry(frame, width=36, show="*")
        password_entry.grid(row=2, column=1, sticky="ew", pady=7)
        password_entry.insert(0, password)

        show_var = tk.BooleanVar(value=False)

        def toggle_password():
            password_entry.configure(show="" if show_var.get() else "*")

        options = ttk.Frame(frame)
        options.grid(row=3, column=1, sticky="w")
        ttk.Checkbutton(options, text="Show", variable=show_var, command=toggle_password).pack(side="left")
        ttk.Button(options, text="Generate", command=lambda: self.generate_password(password_entry)).pack(
            side="left", padx=8
        )

        ttk.Label(frame, text="Notes:").grid(row=4, column=0, sticky="nw", pady=7)
        notes_text = tk.Text(frame, width=36, height=7, wrap="word")
        notes_text.grid(row=4, column=1, sticky="ew", pady=7)
        notes_text.insert("1.0", notes)

        frame.columnconfigure(1, weight=1)

        def save():
            service_value = service_entry.get().strip()
            username_value = username_entry.get().strip()
            password_value = password_entry.get()
            notes_value = notes_text.get("1.0", "end").strip()

            if not service_value or not username_value or not password_value:
                messagebox.showerror(
                    "SafePass",
                    "Service, username and password are required.",
                    parent=popup,
                )
                return

            password_encrypted = encrypt_text(password_value, self.encryption_key)
            notes_encrypted = encrypt_text(notes_value, self.encryption_key)

            if record_id:
                self.db.update_record(
                    record_id,
                    service_value,
                    username_value,
                    password_encrypted,
                    notes_encrypted,
                )
            else:
                self.db.add_record(
                    service_value,
                    username_value,
                    password_encrypted,
                    notes_encrypted,
                )

            popup.destroy()
            self.refresh_records()

        buttons = ttk.Frame(frame)
        buttons.grid(row=5, column=0, columnspan=2, sticky="e", pady=(15, 0))
        ttk.Button(buttons, text="Cancel", command=popup.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Save", command=save).pack(side="right")

        service_entry.focus_set()


if __name__ == "__main__":
    app = SafePassApp()
    app.mainloop()
