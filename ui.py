import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import main_backend as backend


def store_file_ui():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    password = simpledialog.askstring("Password", "Enter password for encryption:", show="*")
    if not password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return

    success, result = backend.store_file_backend(filepath, password)

    if success:
        messagebox.showinfo("Success", f"File stored.\nFile ID: {result}")
    else:
        messagebox.showerror("Error", result)


def retrieve_file_ui():
    file_id = simpledialog.askstring("File ID", "Enter File ID:")
    if not file_id:
        return

    password = simpledialog.askstring("Password", "Enter password for decryption:", show="*")
    if not password:
        return

    output_path = filedialog.asksaveasfilename(title="Save Decrypted File As")
    if not output_path:
        return

    success, message = backend.retrieve_file_backend(file_id, password, output_path)

    if success:
        messagebox.showinfo("Success", message)
    else:
        messagebox.showerror("Error", message)


def list_files_ui():
    files = backend.list_files_backend()

    if not files:
        messagebox.showinfo("Stored Files", "No files stored.")
    else:
        file_list = "\n".join(files)
        messagebox.showinfo("Stored File IDs", file_list)


def delete_file_ui():
    file_id = simpledialog.askstring("Delete File", "Enter File ID to delete:")
    if not file_id:
        return

    deleted = backend.delete_file_backend(file_id)

    if deleted:
        messagebox.showinfo("Success", "File deleted.")
    else:
        messagebox.showerror("Error", "File ID not found.")


def delete_all_ui():
    confirm = messagebox.askyesno("Delete All", "Are you sure you want to delete all files?")
    if confirm:
        backend.delete_all_backend()
        messagebox.showinfo("Success", "All files deleted.")


# ========== MAIN UI WINDOW ========== #

root = tk.Tk()
root.title("Encrypted File Storage System")
root.geometry("400x350")

tk.Label(root, text="Encrypted File Storage System", font=("Arial", 16)).pack(pady=15)

tk.Button(root, text="Store a File", width=30, command=store_file_ui).pack(pady=5)
tk.Button(root, text="Retrieve a File", width=30, command=retrieve_file_ui).pack(pady=5)
tk.Button(root, text="List Stored Files", width=30, command=list_files_ui).pack(pady=5)
tk.Button(root, text="Delete a File", width=30, command=delete_file_ui).pack(pady=5)
tk.Button(root, text="Delete ALL Files", width=30, command=delete_all_ui).pack(pady=5)

root.mainloop()
