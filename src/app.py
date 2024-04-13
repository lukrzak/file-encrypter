from customtkinter import *
import customtkinter
from rsa_generator import generate_keys

import os
import time


customtkinter.set_default_color_theme("src/themes/light.json")

def browse_file():
    global file
    filetypes = (
        ("PDF", "*.pdf"),
        ("C++", "*.cpp")
    )
    file = filedialog.askopenfilenames(filetypes=filetypes)
    selected_files_label.configure(text=", ".join(os.path.basename(file) for file in file))

def encrypting_clicked():
    # Encrypting logic
    global file
    file_name = os.path.basename(file[0])
    key_name = file_name.replace(".", "_")
    disc = filedialog.askdirectory(initialdir="/", title="Select disk")
    print(disc)
    priv_key_path = disc + "/fileEncrypter"
    print(priv_key_path)
    if not os.path.exists(priv_key_path):
        os.makedirs(priv_key_path)
    pub_key_path = "src/publicKeys"
    pin = pin_input.get()

    print("started generating keys")
    try:
        generate_keys(priv_key_path, pub_key_path, pin, key_name)
    except Exception as e:
        print(f"something went wrong: {e}")
    print("ended generating keys")
    perform_operation("Encrypting")

def perform_operation(operation):
    progress_bar.grid(row=6, column=0, columnspan=2, padx=5, pady=5)
    progress_bar.set(0)
    progress_label.configure(text="Operation in progress...")
    for i in range(100):
        time.sleep(0.02)  # Simulate long operation
        progress_bar.set(i/100)
        app.update_idletasks()  # Update interface
    progress_label.configure(text="Operation completed.")
    progress_bar.grid_forget()
    progress_label.grid_forget()
    time.sleep(1)
    app.update_idletasks()

def decrypting_clicked():
 # Dencrypting logic
    global file
    file_name = os.path.basename(file[0])    
    key_name = file_name.replace(".", "_")
    disc = filedialog.askdirectory(initialdir="/", title="Select disk")
    private_key = disc + f"{key_name}_priv.pem"
    public_key = "src/publicKeys/" +  f"{key_name}_pub.pem"
    pin = pin_input.get()
    print(f"{private_key=}")
    print(f"{public_key=}")

    perform_operation("Dencrypting")


# Create main window
app = CTk()
app.title("File Encrypter")
app.geometry("300x300")

file = ""

# File browsing button
browse_button = CTkButton(app, text="Files", command=browse_file, border_width=2)
browse_button.grid(row=2, column=0, padx=5, pady=5, columnspan=2)

# Label for selected files
selected_files_label = CTkLabel(app, text="Selected file(s)")
selected_files_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Decrypting button
decryptingButton = CTkButton(app, text="Decrypting", command=decrypting_clicked, border_width=2)
decryptingButton.grid(row=4, column=1, padx=5, pady=5)

# Encrypting button
encryptingButton = CTkButton(app, text="Encrypting", command=encrypting_clicked, border_width=2)
encryptingButton.grid(row=4, column=0, padx=5, pady=5)

# PIN input
pin_input_label = CTkLabel(app, text="Before operations enter a PIN")
pin_input_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)

pin_input = CTkEntry(app, show="*")
pin_input.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# Progress bar (progress bar)
progress_label = CTkLabel(app, text="")
progress_label.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

progress_bar = CTkProgressBar(app, orientation='horizontal')

# Run main loop
app.mainloop()
