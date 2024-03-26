from customtkinter import *
import customtkinter
from rsa_generator import generate_keys

import os
import time

customtkinter.set_default_color_theme("src/themes/light.json")

def browse_file():
    filetypes = (
        ("PDF", "*.pdf"),
        ("C++", "*.cpp")
    )
    filenames = filedialog.askopenfilenames(filetypes=filetypes)
    selected_files_label.configure(text=", ".join(os.path.basename(file) for file in filenames))

def encrypting_clicked():
    # Encrypting logic
    disc = filedialog.askdirectory(initialdir="/", title="Select disk")
    print("XDDDDDDDDD")
    print(disc)
    priv_key_path = disc + "fileEncrypter"
    print("XDDDDDDDDD22222222")
    print(priv_key_path)
    if not os.path.exists(priv_key_path):
        os.makedirs(priv_key_path)
    pub_key_path = "./publicKeys"
    pin = pin_window()
    generate_keys(priv_key_path, pub_key_path, pin)
    perform_operation("Encrypting")

def perform_operation(operation):
    progress_bar.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
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

def pin_window():
    pin_window = CTkToplevel(app)
    pin_window.title("Enter PIN")

    def enter_pressed(event):
        entered_pin = pin_entry.get()
        return entered_pin

    pin_label = CTkLabel(pin_window, text="Enter PIN:")
    pin_label.pack()

    pin_entry = CTkEntry(pin_window, show="*")
    pin_entry.pack()

    # Label to display incorrect PIN message
    pin_error_label = CTkLabel(pin_window, text="")
    pin_error_label.pack()

    # Handle Enter key press
    pin_entry.bind("<Return>", enter_pressed)
    

def decrypting_clicked():
    # Create new window for entering PIN
    pin_window = CTkToplevel(app)
    pin_window.title("Enter PIN")

    def enter_pressed(event):
        entered_pin = pin_entry.get()
        # Check PIN correctness
        if entered_pin == "1234":  # Example PIN
            pin_window.destroy()
            perform_operation("Decrypting")
        else:
            # Incorrect PIN message
            pin_error_label.configure(text="Incorrect PIN!")

    pin_label = CTkLabel(pin_window, text="Enter PIN:")
    pin_label.pack()

    pin_entry = CTkEntry(pin_window, show="*")
    pin_entry.pack()

    # Label to display incorrect PIN message
    pin_error_label = CTkLabel(pin_window, text="")
    pin_error_label.pack()

    # Handle Enter key press
    pin_entry.bind("<Return>", enter_pressed)

# Create main window
app = CTk()
app.title("File Encrypter")
app.geometry("300x200")

filenames = ""

# File browsing button
browse_button = CTkButton(app, text="Files", command=browse_file, border_width=2)
browse_button.grid(row=0, column=0, padx=5, pady=5, columnspan=2)

# Label for selected files
selected_files_label = CTkLabel(app, text="Selected file(s)")
selected_files_label.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# Decrypting button
decryptingButton = CTkButton(app, text="Decrypting", command=decrypting_clicked, border_width=2)
decryptingButton.grid(row=2, column=1, padx=5, pady=5)

# Encrypting button
encryptingButton = CTkButton(app, text="Encrypting", command=encrypting_clicked, border_width=2)
encryptingButton.grid(row=2, column=0, padx=5, pady=5)

# Progress bar (progress bar)
progress_label = CTkLabel(app, text="")
progress_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

progress_bar = CTkProgressBar(app, orientation='horizontal')


# Run main loop
app.mainloop()
