from customtkinter import *
import customtkinter
from rsa_generator import generate_keys

import tkinter as tk
import file_cipher as fc
import os
import subprocess

customtkinter.set_default_color_theme("src/themes/light.json")


class AppWindow:
        def __init__(self) -> None:
            self.app = CTk()
            self.app.title("File Encrypter")
            self.app.geometry("450x350")
            self.found_keys = self.find_keys()
            self.keys_names = None
            self.generate_window()

        def get_removable_drives(self) -> list:
            drives = []
            result = subprocess.run(['wmic', 'logicaldisk', 'get', 'caption,drivetype'], stdout=subprocess.PIPE)
            output = result.stdout.decode('utf-8')
            lines = output.split('\n')
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) == 2 and int(parts[1]) == 2:  # Check if drive type is removable
                    drives.append(parts[0])
            return drives

        def find_keys(self) -> list:
            keys = []
            removable_drives = self.get_removable_drives()
            for drive in removable_drives:
                key_path = drive + "/fileEncrypter"
                if os.path.exists(key_path):
                    dirs = os.listdir(key_path)
                    keys.append((dirs[0], f"{key_path}/{dirs[0]}"))
            return keys

        def generate_window(self) -> None:
            enc_image = tk.PhotoImage(file="src/themes/encrypt.png")
            dec_image = tk.PhotoImage(file="src/themes/decrypt.png")
            reg_image = tk.PhotoImage(file="src/themes/register.png")
            sign_image = tk.PhotoImage(file="src/themes/sign.png")
            check_image = tk.PhotoImage(file="src/themes/check.png")
            self.left_frame = CTkFrame(self.app, border_width=1)
            self.left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

            self.right_frame = CTkFrame(self.app, border_width=1)
            self.right_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

            self.info_label = CTkLabel(self.right_frame, text="")
            self.title = CTkLabel(self.right_frame, text="Welcome", bg_color="#2F8886", width=140, corner_radius=500)
            self.next_button = CTkLabel(self.right_frame, text="")

            # Encrypting button
            self.encryptingButton = CTkButton(self.left_frame, text="Encrypting          ",
                                              command=lambda: self.select_key(encrypt=True), border_width=2,
                                              image=enc_image, compound="left")
            self.encryptingButton.pack(padx=2, pady=5)

            # Decrypting button
            decryptingButton = CTkButton(self.left_frame, text="Decrypting          ",
                                         command=lambda: self.select_key(encrypt=False), border_width=2,
                                         image=dec_image, compound="left")
            decryptingButton.pack(padx=2, pady=5)

            # Sign button
            signButton = CTkButton(self.left_frame, text="Sign file                ",
                                   command=lambda: self.select_key(sign_file=True), border_width=2,
                                   image=sign_image, compound="left")
            signButton.pack(padx=2, pady=5)

            # Check button
            checkButton = CTkButton(self.left_frame, text="Check signature",
                                    command=lambda: self.file_selection(check_sing=True), border_width=2,
                                    image=check_image, compound="left")
            checkButton.pack(padx=2, pady=5)

            # Register key
            registerKeyButton = CTkButton(self.left_frame, text="  Register Key ",
                                          command=self.register_key, border_width=2,
                                          image=reg_image, compound="left")
            registerKeyButton.pack(pady=10)

            # Label for finded keys
            self.refresh_found_keys()

            self.title.pack(pady=5)
            self.info_label.pack()
            self.app.mainloop()

        def refresh_found_keys(self):
            if hasattr(self, 'keys_found_label'): 
                self.keys_found_label.destroy()
            self.key_image = tk.PhotoImage(file="src/themes/key.png")
            self.found_keys = self.find_keys()
            self.keys_found_label = CTkLabel(self.left_frame, text="Keys found:")
            self.keys_found_label.pack()
            if self.keys_names is not None:
                for k in self.keys_names:
                    k.destroy()
            self.keys_names = []
            for index, key in enumerate(self.found_keys):
                keys_name_label = CTkLabel(self.left_frame, text=f" {key[0]}", height=10, image=self.key_image, compound="left")
                keys_name_label.pack()
                self.keys_names.append(keys_name_label)

        def check_keys(self) -> bool:
            self.found_keys = self.find_keys()
            if not self.found_keys:
                self.info_label.configure(text="No Keys Found")
                return False
            return True

        def destroy_elements(self, elements):
            for element in elements:
                element.destroy()

        def select_key(self, encrypt: bool = False, sign_file: bool = False) -> None:
            self.refresh_found_keys()
            self.clear_view()
            self.files_selected = None
            if not self.check_keys():
                return
            
            if sign_file:
                self.title.configure(text="Sign file")
            else:
                self.title.configure(text=f"{"ENCRYPT" if encrypt else "DECRYPT"}")
            self.info_label.configure(text="Select key:")
            self.selected_key = StringVar()
            self.radio_buttons_for_keys = []
            for index, key in enumerate(self.found_keys):
                key_name = key[0]
                key_path = key[1]
                rb = CTkRadioButton(self.right_frame, text=key_name, variable=self.selected_key, value=key_path)
                rb.pack()
                self.radio_buttons_for_keys.append(rb)

            self.next_button = CTkButton(self.right_frame, text="Next", command=lambda: self.write_pin(encrypt, sign_file))
            self.next_button.pack(side="bottom", pady=5)

        def write_pin(self, encrypt: bool, sign_file: bool) -> None:
            self.clear_view()
            
            self.selected_key = self.selected_key.get()
            self.info_label.configure(text=f'Write pin for "{os.path.basename(os.path.normpath(self.selected_key))}" key')

            self.pin_input = CTkEntry(self.right_frame, show="*")
            self.pin_input.pack()

            self.next_button = CTkButton(self.right_frame, text="Next", command=lambda: self.file_selection(encrypt, sign_file))
            self.next_button.pack(side="bottom", pady=5)

        def select_file(self, encrypt: bool, sign_file: bool, check_sing: bool, signature: bool = False) -> None:
            self.signature_filetypes = (("XML", "*.xml"),)
            self.filetypes_for_encryp = (("TXT", "*.txt"), ("C++", "*.cpp"), ("PDF", "*.pdf"), ("PNG", "*.png"), ("ENC", "*.enc"))
            self.filetypes_for_decryp = (("Encrypted File", "*.enc"),)

            file_types = self.filetypes_for_encryp if (encrypt or sign_file or check_sing) else self.filetypes_for_decryp
            if not signature:
                self.selected_file = filedialog.askopenfilename(filetypes=self.signature_filetypes if signature else file_types)
                self.selected_file_name.configure(text=os.path.basename(self.selected_file))
            else:
                self.selected_signature_file = filedialog.askopenfilename(filetypes=self.signature_filetypes if signature else file_types)
                self.selected_signature_file_name.configure(text=os.path.basename(self.selected_signature_file))

        def file_selection(self, encrypt: bool = False, sign_file: bool = False, check_sing: bool = False) -> None:
            self.clear_view()

            if check_sing:
                self.title.configure(text="Check signature")

            self.selected_file = None
            self.selected_signature_file = None

            if sign_file:
                self.info_label.configure(text=f"Select file to sign")
            elif check_sing:
                self.info_label.configure(text=f"Select file to check signature")
            else:
                self.info_label.configure(text=f"Select file to {"encrytp" if encrypt else "decrypt"}")

            self.select_file_button = CTkButton(self.right_frame, text="Select file", command=lambda: self.select_file(encrypt, sign_file, check_sing))
            self.select_file_button.pack()

            self.selected_file_name = CTkLabel(self.right_frame, text="")
            self.selected_file_name.pack()
            self.info_label.configure(text=f"")
  
            if sign_file or encrypt:
                self.select_signature_file_button = CTkButton(self.right_frame, text="Select signature output file", command=lambda: self.select_output_file(encrypt, signature = True))
                self.select_signature_file_button.pack()
            else:
                self.select_signature_file_button = CTkButton(self.right_frame, text="Select signature file", command=lambda: self.select_file(encrypt, sign_file, check_sing, signature = True))
                self.select_signature_file_button.pack()

            self.selected_signature_file_name = CTkLabel(self.right_frame, text="")
            self.selected_signature_file_name.pack()

            if sign_file:
                self.next_button = CTkButton(self.right_frame, text="Sign", command=lambda: self.sign_file())
            elif check_sing:
                self.next_button = CTkButton(self.right_frame, text="Check", command=lambda: self.check_sign_file())
            else:
                self.next_button = CTkButton(self.right_frame, text="Next", command=lambda: self.output_selection(encrypt))
            self.next_button.pack(side="bottom", pady=5)

        def select_output_file(self, encrypt: bool, signature: bool = False) -> None:
            self.file_output_path = None
            self.output_types_for_decryp = (("TXT", "*.txt"), ("C++", "*.cpp"), ("PDF", "*.pdf"), ("PNG", "*.png"))
            self.output_types_for_encryp = (("Encrypted File", "*.enc"),)
            self.output_signature_type = (("XML", "*.xml"),)
            file_types = self.output_types_for_encryp if encrypt else self.output_types_for_decryp
            defaultextension = ".enc" if encrypt else ".txt"
            if not signature:
                self.file_output_path = filedialog.asksaveasfilename(title="Output file",filetypes=file_types, defaultextension=defaultextension)
                self.signature_output_path  = os.path.splitext(self.file_output_path)[0] + ".signature.xml"
                self.selected_output_name.configure(text=self.file_output_path)
            else:
                defaultextension = ".xml"
                self.selected_signature_file = filedialog.asksaveasfilename(title="Output file",filetypes=self.output_signature_type, defaultextension=defaultextension)
                self.selected_signature_file_name.configure(text=os.path.basename(self.selected_signature_file))

        def output_selection(self, encrypt: bool) -> None:
            if self.selected_file is None:
                return
            
            self.clear_view()

            self.file_output_path = None

            self.info_label.configure(text=f"Select output file")

            self.select_output_file_button = CTkButton(self.right_frame, text="Select output file", command=lambda: self.select_output_file(encrypt))
            self.select_output_file_button.pack()

            self.selected_file_label = CTkLabel(self.right_frame, text="Output path:")
            self.selected_file_label.pack()

            self.selected_output_name = CTkLabel(self.right_frame, text="")
            self.selected_output_name.pack()

            if encrypt:
                self.next_button = CTkButton(self.right_frame, text=f"{"Encrypt" if encrypt else "Decrypt"}", command=self.encrypt)
            else:
                self.next_button = CTkButton(self.right_frame, text=f"{"Encrypt" if encrypt else "Decrypt"}", command=self.decrypt)
            self.next_button.pack(side="bottom", pady=5)

        def encrypt(self) -> None:
            if self.file_output_path is None:
                return
            
            self.clear_view()

            default_signature_file = os.path.splitext(self.selected_file)[0] + ".signature.xml"
            signature_file = self.selected_signature_file if self.selected_signature_file else default_signature_file
            self.info_label.configure(text=f"Encrypting in process...")
            pub_key_path = f"{self.selected_key}/PubKey.pem"
            priv_key_path = f"{self.selected_key}/PrivKey.pem"
            cert_path = f"{self.selected_key}/Cert.dem"
            try:
                fc.cipher_file(self.selected_file, pub_key_path, "encrypt", None, self.file_output_path, "file")
                fc.generate_file_signature(self.file_output_path, priv_key_path, cert_path, self.pin, signature_file)
                self.info_label.configure(text=f"Encrypting done! :)")
            except Exception as e:
                self.info_label.configure(text=f"{e} :(")

        def decrypt(self) -> None:
            if self.file_output_path is None:
                return

            self.clear_view()
            priv_key_path = f"{self.selected_key}/PrivKey.pem"
            default_signature_file = os.path.splitext(self.selected_file)[0] + ".signature.xml"
            signature_file = self.selected_signature_file if self.selected_signature_file else default_signature_file
            sign = ""

            try:
                self.info_label.configure(text=f"Checking file signature...")
                if not fc.verify_signature(self.selected_file, signature_file):
                    sign = "Bad signature"
            except Exception as e:
                self.info_label.configure(text=f"{e} :(")

            try:            
                self.info_label.configure(text=f"Decrypting in process...")
                fc.cipher_file(self.selected_file, priv_key_path, "decrypt", self.pin, self.file_output_path, "file")
                self.info_label.configure(text=f"Decrypting done! :)")
            except Exception as e:
                self.info_label.configure(text=f"{e} :( {sign}")

        def sign_file(self) -> None:
            self.clear_view()
            priv_key_path = f"{self.selected_key}/PrivKey.pem"
            default_signature_file = os.path.splitext(self.selected_file)[0] + ".signature.xml"
            signature_file = self.selected_signature_file if self.selected_signature_file else default_signature_file
            cert_path = f"{self.selected_key}/Cert.dem"
            self.info_label.configure(text=f"Signing file ...")
            fc.generate_file_signature(self.selected_file, priv_key_path, cert_path, self.pin, signature_file)
            self.info_label.configure(text=f"Signature generated! :)")

        def check_sign_file(self) -> None:
            self.clear_view()
            default_signature_file = os.path.splitext(self.selected_file)[0] + ".signature.xml"
            signature_file = self.selected_signature_file if self.selected_signature_file else default_signature_file
            self.info_label.configure(text=f"Checking signature ... {self.selected_file}")
            if fc.verify_signature(self.selected_file, signature_file):
                self.info_label.configure(text=f"Signature is correct")
            else:
                self.info_label.configure(text=f"Bad signature")


        def register_key(self) -> None:
            self.refresh_found_keys()
            self.clear_view()
            self.title.configure(text="REGISTER KEY")
            self.info_label.configure(text="Enter pin for key")

            self.pin_input = CTkEntry(self.right_frame, show="*")
            self.pin_input.pack()

            self.enter_name_label = CTkLabel(self.right_frame, text="Enter name for key")
            self.enter_name_label.pack()

            self.name_input = CTkEntry(self.right_frame)
            self.name_input.pack()

            self.selected_disk_label = CTkLabel(self.right_frame, text="Select pendrive")
            self.selected_disk_label.pack()

            removable_drives = self.get_removable_drives()
            keys = self.find_keys()
            removable_drives_no_keys = []

            for driver in removable_drives:
                is_key = False
                for key in keys:
                    if key[1][0] == driver[0]:
                        is_key= True
                if not is_key:
                    removable_drives_no_keys.append(driver)

            self.selected_driver = StringVar(value="other")
            self.radio_buttons_for_driver = []
            for index, driver in enumerate(removable_drives_no_keys):
                rb = CTkRadioButton(self.right_frame, text=driver, variable=self.selected_driver, value=driver)
                rb.pack()
                self.radio_buttons_for_driver.append(rb)
            
            self.next_button = CTkButton(self.right_frame, text="Register", command=self.generate_registered_key)
            self.next_button.pack(side="bottom", pady=5)

        def clear_view(self):
            if hasattr(self, 'name_input'):
                if self.name_input is not None:
                    if self.name_input.winfo_exists(): 
                        self.key_name = self.name_input.get()
                    self.name_input.destroy()
            if hasattr(self, 'enter_pin_label'): self.enter_pin_label.destroy()
            if hasattr(self, 'enter_name_label'): self.enter_name_label.destroy()
            if hasattr(self, 'selected_disk_label'): self.selected_disk_label.destroy()
            if hasattr(self, 'next_button'): self.next_button.destroy()
            if hasattr(self, 'radio_buttons_for_driver'): 
                if self.radio_buttons_for_driver is not None:
                    self.destroy_elements(self.radio_buttons_for_driver)
                    self.radio_buttons_for_driver = None
            if hasattr(self, 'pin_input'): 
                if self.pin_input is not None:
                    if self.pin_input.winfo_exists(): self.pin = self.pin_input.get()
                    self.pin_input.destroy()
            if hasattr(self, 'select_output_file_button'): self.select_output_file_button.destroy()
            if hasattr(self, 'selected_file_label'): self.selected_file_label.destroy()
            if hasattr(self, 'selected_file_label'): self.selected_file_label.destroy()
            if hasattr(self, 'selected_output_name'): self.selected_output_name.destroy()
            if hasattr(self, 'select_file_button'): self.select_file_button.destroy()
            if hasattr(self, 'selected_file_name'): self.selected_file_name.destroy()
            
            if hasattr(self, 'selected_signature_file_label'): self.selected_signature_file_label.destroy()
            if hasattr(self, 'selected_signature_file_label'): self.selected_signature_file_label.destroy()
            if hasattr(self, 'select_signature_file_button'): self.select_signature_file_button.destroy()
            if hasattr(self, 'selected_signature_file_name'): self.selected_signature_file_name.destroy()

            if hasattr(self, 'radio_buttons_for_keys'):
                if self.radio_buttons_for_keys is not None:
                    self.destroy_elements(self.radio_buttons_for_keys)
                    self.radio_buttons_for_keys = None

        def generate_registered_key(self) -> None:
            self.clear_view()

            key_path = f"{self.selected_driver.get()}/fileEncrypter/{self.key_name}"
            os.makedirs(key_path)

            pub_key_path = f"{key_path}/PubKey.pem"
            priv_key_path = f"{key_path}/PrivKey.pem"
            cert_path = f"{key_path}/Cert.dem"

            try:
                self.info_label.configure(text="Working...")
                generate_keys(priv_key_path, pub_key_path, self.pin, cert_path)
                self.info_label.configure(text="Key Registered! :)")
            except Exception as e:
                self.info_label.configure(text=f"{e} :(")
            self.refresh_found_keys()


AppWindow()
