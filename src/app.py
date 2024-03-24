import tkinter as tk
from tkinter import filedialog
from tkinter import ttk  # Import ttk for styled widgets

import os
import time
import pyudev 

def browse_file():
    global filenames
    filetypes = (
        ("PDF", "*.pdf"),
        ("C++", "*.cpp")
    )
    filenames = filedialog.askopenfilenames(filetypes=filetypes)
    selected_files_label.config(text=", ".join(os.path.basename(file) for file in filenames))

def encrypting_clicked():
    global filenames
    # Encrypting logic
    perform_operation("Encrypting")
   
def perform_operation(operation):
    global filenames   
    progress_label.pack()
    progress_bar.pack()
    # Simulate operation
    progress_label.config(text="Operation in progress...")
    for i in range(100):
        time.sleep(0.02)  # Simulate long operation
        progress_bar["value"] = i
        root.update_idletasks()  # Update interface
    progress_label.config(text="Operation completed.")
    time.sleep(1)
    progress_label.forget()
    progress_bar.forget()

def decrypting_clicked():
    # Create new window for entering PIN
    pin_window = tk.Toplevel(root)
    pin_window.title("Enter PIN")

    def enter_pressed(event):
        entered_pin = pin_entry.get()
        # Check PIN correctness
        if entered_pin == "1234":  # Example PIN
            pin_window.destroy()
            perform_operation("Decrypting")
        else:
            # Incorrect PIN message
            pin_error_label.config(text="Incorrect PIN!")

    pin_label = ttk.Label(pin_window, text="Enter PIN:")
    pin_label.pack()

    pin_entry = ttk.Entry(pin_window, show="*")
    pin_entry.pack()

    # Label to display incorrect PIN message
    pin_error_label = ttk.Label(pin_window, text="", foreground="red")
    pin_error_label.pack()

    # Handle Enter key press
    pin_entry.bind("<Return>", enter_pressed)

def on_usb_insert(event):
    global filenames
    print("USB device inserted:", event.device_node)

# Create main window
root = tk.Tk()
root.title("File Encrypter")
root.geometry("300x150")

filenames = ""

# Create button style using ttk
style = ttk.Style()
style.configure('TButton', font=('calibri', 10, 'bold'), borderwidth='4')

# File browsing button
browse_button = ttk.Button(root, text="Files", command=browse_file, style='TButton')
browse_button.pack()

# Label for selected files
selected_files_label = ttk.Label(root, text="Selected file(s)")
selected_files_label.pack()

# Decrypting button
decryptingButton = ttk.Button(root, text="Decrypting", command=decrypting_clicked, style='TButton')
decryptingButton.pack()

# Encrypting button
encryptingButton = ttk.Button(root, text="Encrypting", command=encrypting_clicked, style='TButton')
encryptingButton.pack()

# Progress bar (progress bar)
progress_frame = ttk.Frame(root)
progress_frame.pack(pady=10)

progress_label = ttk.Label(progress_frame, text="")
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=250, mode="determinate")

# Run main loop
root.mainloop()

context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem='usb')
observer = pyudev.MonitorObserver(monitor, on_usb_insert)
observer.start()