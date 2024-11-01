import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

file_changes = {}
dir_changes = {}

def filter_filename(filename):
    base_name, ext = os.path.splitext(filename)
    base_name = base_name.replace('.', ' ').replace('(', '').replace(')', '')

    pattern = re.compile(
        r'(?P<title>.+?)\s?(?P<details>(?:FRENCH|BluRay|REMUX|MULTi|VF2|\d{4}|S\d{2}E\d{2}|1080|720|BD|UHD|HDR10|hybrid|DV|x265|x264)+)', 
        re.IGNORECASE
    )

    match = pattern.search(base_name)
    if match:
        title = match.group('title').strip()
        details = match.group('details').strip()
        filtered_name = f"{title} {details}{ext}"
        return filename, filtered_name
    else:
        return filename, base_name + ext

def filter_directory_name(directory_name):
    directory_name = directory_name.replace('.', ' ').replace('(', '').replace(')', '')

    pattern = re.compile(
        r'(?P<title>.+?)\s?(?P<details>(?:FRENCH|BluRay|REMUX|MULTi|VF2|\d{4}|S\d{2}E\d{2}|1080|720|BD|UHD|HDR10|hybrid|DV|x265|x264)+)', 
        re.IGNORECASE
    )

    match = pattern.search(directory_name)
    if match:
        title = match.group('title').strip()
        details = match.group('details').strip()
        filtered_name = f"{title} {details}"
        return directory_name, filtered_name
    else:
        return directory_name, directory_name

def rename_files_and_directories_in_directory(directory):
    log_text.insert(tk.END, f"Starting to rename files and directories in: {directory}\n")

    for root, dirs, files in os.walk(directory, topdown=False):
        # Renommer les fichiers
        for file in files:
            original_file_path = os.path.join(root, file)
            original_file_name, filtered_file_name = filter_filename(file)
            new_file_path = os.path.join(root, filtered_file_name)

            if original_file_path != new_file_path:
                try:
                    os.rename(original_file_path, new_file_path)
                    file_changes[new_file_path] = original_file_path
                    log_text.insert(tk.END, f"{original_file_name} ===> {filtered_file_name}\n")
                except FileExistsError:
                    log_text.insert(tk.END, f"Error: File already exists: {new_file_path}\n")
                except Exception as e:
                    log_text.insert(tk.END, f"Error renaming {original_file_path}: {e}\n")

        # Renommer les répertoires
        for dir in dirs:
            original_dir_path = os.path.join(root, dir)
            original_dir_name, filtered_dir_name = filter_directory_name(dir)
            new_dir_path = os.path.join(root, filtered_dir_name)

            if original_dir_path != new_dir_path:
                try:
                    os.rename(original_dir_path, new_dir_path)
                    dir_changes[new_dir_path] = original_dir_path
                    log_text.insert(tk.END, f"{original_dir_name} ===> {filtered_dir_name}\n")
                except FileExistsError:
                    log_text.insert(tk.END, f"Error: Directory already exists: {new_dir_path}\n")
                except Exception as e:
                    log_text.insert(tk.END, f"Error renaming {original_dir_path}: {e}\n")
    log_text.insert(tk.END, "Renaming process completed.\n")

def revert_changes():
    log_text.insert(tk.END, "Reverting changes...\n")
    for new_path, original_path in sorted(file_changes.items(), key=lambda x: len(x[0]), reverse=True):
        try:
            os.rename(new_path, original_path)
            log_text.insert(tk.END, f"Reverted: {new_path} -> {original_path}\n")
        except Exception as e:
            log_text.insert(tk.END, f"Error reverting {new_path}: {e}\n")
    # Revert directory changes
    for new_path, original_path in sorted(dir_changes.items(), key=lambda x: len(x[0]), reverse=True):
        try:
            os.rename(new_path, original_path)
            log_text.insert(tk.END, f"Reverted: {new_path} -> {original_path}\n")
        except Exception as e:
            log_text.insert(tk.END, f"Error reverting {new_path}: {e}\n")
    log_text.insert(tk.END, "Reversion process completed.\n")

def start_renaming():
    global directory
    directory = filedialog.askdirectory()
    if directory:
        log_text.delete(1.0, tk.END)  
        rename_files_and_directories_in_directory(directory)
        confirmation_frame.pack(pady=10)
    else:
        messagebox.showwarning("Warning", "Aucun répertoire sélectionné.")

def confirm_changes():
    if confirmation_var.get() == "yes":
        messagebox.showinfo("Info", "Changements conservés.")
    else:
        revert_changes()
        messagebox.showinfo("Info", "Changements annulés.")
    confirmation_frame.pack_forget()
root = tk.Tk()
root.title("Renommage de fichiers et répertoires")

width = 800
height = 600
root.geometry(f"{width}x{height}")

root.configure(bg='#24292e')

style = ttk.Style()
style.configure("TFrame", background="#24292e")
style.configure("TButton", background="#000000", foreground="black", font=("Helvetica", 12, "bold"), padding=10)
style.configure("TLabel", background="#24292e", foreground="white", font=("Helvetica", 12), padding=10)
style.configure("TRadiobutton", background="#24292e", foreground="white", font=("Helvetica", 12), padding=10)
style.configure("TText", background="#1c1e22", foreground="white", font=("Helvetica", 10), padding=10)

frame = ttk.Frame(root, padding="20")
frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

btn_select_directory = ttk.Button(frame, text="Sélectionner un répertoire", command=start_renaming)
btn_select_directory.pack(pady=10)

log_text = tk.Text(frame, wrap="word", height=20, width=80, bg="#1c1e22", fg="white", font=("Helvetica", 10), bd=2, relief="solid")
log_text.pack(pady=10)

confirmation_frame = ttk.Frame(root, padding="20")
confirmation_var = tk.StringVar(value="no")

label_confirmation = ttk.Label(confirmation_frame, text="Tout est bon?")
label_confirmation.pack(side="left")

radio_yes = ttk.Radiobutton(confirmation_frame, text="Oui", variable=confirmation_var, value="yes")
radio_yes.pack(side="left")

radio_no = ttk.Radiobutton(confirmation_frame, text="Non", variable=confirmation_var, value="no")
radio_no.pack(side="left")

btn_confirm = ttk.Button(confirmation_frame, text="Confirmer", command=confirm_changes)
btn_confirm.pack(side="left", padx=10)

root.mainloop()
