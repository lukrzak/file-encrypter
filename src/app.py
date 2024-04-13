from customtkinter import *
import customtkinter
from rsa_generator import generate_keys

import file_cipher as fc
import os
import subprocess

customtkinter.set_default_color_theme("src/themes/light.json")


class AppWindow:
        def __init__(self) -> None:
            self.app = CTk()
            self.app.title("File Encrypter")
            self.app.geometry("550x350")
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
            self.info_label = CTkLabel(self.app, text="")
            self.title = CTkLabel(self.app, text="Welcome")
            self.next_button = CTkLabel(self.app, text="")

            # Encrypting button
            self.encryptingButton = CTkButton(self.app, text="Encrypting", command=lambda: self.select_key(encrypt=True), border_width=2)
            self.encryptingButton.grid(row=0, column=0, padx=2, pady=2)

            # Decrypting button
            decryptingButton = CTkButton(self.app, text="Decrypting", command=lambda: self.select_key(encrypt=False), border_width=2)
            decryptingButton.grid(row=0, column=1, padx=2, pady=2)

            # Register key
            registerKeyButton = CTkButton(self.app, 
                                          text="                                  Register Key                                  ", 
                                          command=self.register_key, border_width=2)
            registerKeyButton.grid(row=1, column=0, columnspan=2, padx=2, pady=2)

            # Label for finded keys
            self.refresh_found_keys()

            self.title.grid(row=0, column=2, columnspan=2, padx=2, pady=2)
            self.info_label.grid(row=1, column=2, columnspan=2, padx=2, pady=2)
            self.next_button
            self.app.mainloop()

        def refresh_found_keys(self):
            self.found_keys = self.find_keys()
            self.keys_found_label = CTkLabel(self.app, text="Keys found:")
            self.keys_found_label.grid(row=3, column=0, padx=2, pady=2)
            if self.keys_names is not None:
                for k in self.keys_names:
                    k.destroy()
            self.keys_names = []
            for index, key in enumerate(self.found_keys):
                keys_name_label = CTkLabel(self.app, text=key[0])
                keys_name_label.grid(row=4+index, column=0, padx=2, pady=2)
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

        def select_key(self, encrypt: bool) -> None:
            self.refresh_found_keys()
            self.clear_view()
            self.files_selected = None
            if not self.check_keys():
                return

            self.title.configure(text=f"{"ENCRYPT" if encrypt else "DECRYPT"}")
            self.info_label.configure(text="Select key:")
            self.selected_key = StringVar()
            self.radio_buttons_for_keys = []
            for index, key in enumerate(self.found_keys):
                key_name = key[0]
                key_path = key[1]
                rb = CTkRadioButton(self.app, text=key_name, variable=self.selected_key, value=key_path)
                rb.grid(row=2 + index, column=2, padx=2, pady=2)
                self.radio_buttons_for_keys.append(rb)

            self.next_button = CTkButton(self.app, text="Next", command=lambda: self.write_pin(encrypt))
            self.next_button.grid(row=11, column=2, padx=2, pady=2)

        def write_pin(self, encrypt: bool) -> None:
            self.clear_view()
            
            self.selected_key = self.selected_key.get()
            self.info_label.configure(text=f'Write pin for "{os.path.basename(os.path.normpath(self.selected_key))}" key')

            self.pin_input = CTkEntry(self.app, show="*")
            self.pin_input.grid(row=10, column=2, columnspan=2, padx=2, pady=2)

            self.next_button = CTkButton(self.app, text="Next", command=lambda: self.file_selection(encrypt))
            self.next_button.grid(row=11, column=2, padx=2, pady=2)

        def select_file(self, encrypt: bool) -> None:
            self.selected_file = None
            self.filetypes_for_encryp = (("TXT", "*.txt"), ("C++", "*.cpp"))
            self.filetypes_for_decryp = (("Encrypted File", "*.enc"),)
            file_types = self.filetypes_for_encryp if encrypt else self.filetypes_for_decryp
            self.selected_file = filedialog.askopenfilename(filetypes=file_types)
            self.selected_file_name.configure(text=os.path.basename(self.selected_file))

        def file_selection(self, encrypt: bool) -> None:
            self.clear_view()

            self.selected_file = None

            self.info_label.configure(text=f"Select file to {"encrytp" if encrypt else "decrypt"}")

            self.select_file_button = CTkButton(self.app, text="Select file", command=lambda: self.select_file(encrypt))
            self.select_file_button.grid(row=3, column=2, padx=2, pady=2)

            self.selected_file_label = CTkLabel(self.app, text="Selected file:")
            self.selected_file_label.grid(row=4, column=2, padx=2, pady=2)

            self.selected_file_name = CTkLabel(self.app, text="")
            self.selected_file_name.grid(row=5, column=2, padx=2, pady=2)

            self.next_button = CTkButton(self.app, text="Next", command=lambda: self.output_selection(encrypt))
            self.next_button.grid(row=10, column=2, padx=2, pady=2)

        def select_output_file(self, encrypt: bool) -> None:
            self.file_output_path = None
            self.output_types_for_decryp = (("TXT", "*.txt"), ("C++", "*.cpp"))
            self.output_types_for_encryp = (("Encrypted File", "*.enc"),)
            file_types = self.output_types_for_encryp if encrypt else self.output_types_for_decryp
            defaultextension = ".enc" if encrypt else ".txt"
            self.file_output_path = filedialog.asksaveasfilename(title="Output file",filetypes=file_types, defaultextension=defaultextension)
            self.signature_output_path  = os.path.splitext(self.file_output_path)[0] + ".signature.xml"
            self.selected_output_name.configure(text=self.file_output_path)

        def output_selection(self, encrypt: bool) -> None:
            if self.selected_file is None:
                return
            
            self.clear_view()

            self.file_output_path = None

            self.info_label.configure(text=f"Select output file")

            self.select_output_file_button = CTkButton(self.app, text="Select output file", command=lambda: self.select_output_file(encrypt))
            self.select_output_file_button.grid(row=3, column=2, padx=2, pady=2)

            self.selected_file_label = CTkLabel(self.app, text="Output path:")
            self.selected_file_label.grid(row=4, column=2, padx=2, pady=2)

            self.selected_output_name = CTkLabel(self.app, text="")
            self.selected_output_name.grid(row=5, column=2, padx=2, pady=2)

            if encrypt:
                self.next_button = CTkButton(self.app, text=f"{"Encrypt" if encrypt else "Decrypt"}", command=self.encrypt)
            else:
                self.next_button = CTkButton(self.app, text=f"{"Encrypt" if encrypt else "Decrypt"}", command=self.decrypt)
            self.next_button.grid(row=10, column=2, padx=2, pady=2)

        def encrypt(self) -> None:
            if self.file_output_path is None:
                return
            
            self.clear_view()

            self.info_label.configure(text=f"Encrypting in process...")
            pub_key_path = f"{self.selected_key}/PubKey.pem"
            priv_key_path = f"{self.selected_key}/PrivKey.pem"
            cert_path = f"{self.selected_key}/Cert.dem"
            try:
                fc.cipher_file(self.selected_file, pub_key_path, "encrypt", None, self.file_output_path, "file")
                fc.generate_file_signature(self.file_output_path, priv_key_path, cert_path, self.pin, self.signature_output_path)
                self.info_label.configure(text=f"Encrypting done! :)")
            except Exception as e:
                self.info_label.configure(text=f"{e} :(")

        def decrypt(self) -> None:
            if self.file_output_path is None:
                return

            self.clear_view()

            self.info_label.configure(text=f"Decrypting in process...")
            pub_key_path = f"{self.selected_key}/PubKey.pem"
            priv_key_path = f"{self.selected_key}/PrivKey.pem"
            cert_path = f"{self.selected_key}/Cert.dem"
            try:
                fc.cipher_file(self.selected_file, priv_key_path, "decrypt", self.pin, self.file_output_path, "file")
                self.info_label.configure(text=f"Decrypting done! :)")
            except Exception as e:
                self.info_label.configure(text=f"{e} :(")

        def register_key(self) -> None:
            self.refresh_found_keys()
            self.clear_view()
            self.title.configure(text="REGISTER KEY")
            self.info_label.configure(text="Enter pin for key")

            self.pin_input = CTkEntry(self.app, show="*")
            self.pin_input.grid(row=2, column=2, columnspan=2, padx=2, pady=2)

            self.enter_name_label = CTkLabel(self.app, text="Enter name for key")
            self.enter_name_label.grid(row=3, column=2, padx=2, pady=2)

            self.name_input = CTkEntry(self.app)
            self.name_input.grid(row=4, column=2, columnspan=2, padx=2, pady=2)

            self.selected_disk_label = CTkLabel(self.app, text="Select pendrive")
            self.selected_disk_label.grid(row=5, column=2, padx=2, pady=2)

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
                rb = CTkRadioButton(self.app, text=driver, variable=self.selected_driver, value=driver)
                rb.grid(row=6 + index, column=2, padx=2, pady=2)
                self.radio_buttons_for_driver.append(rb)
            
            self.next_button = CTkButton(self.app, text="Register", command=self.generate_registered_key)
            self.next_button.grid(row=10, column=2, padx=2, pady=2)

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
            if hasattr(self, 'selected_output_name'): self.selected_output_name.destroy()
            if hasattr(self, 'select_file_button'): self.select_file_button.destroy()
            if hasattr(self, 'selected_file_name'): self.selected_file_name.destroy()
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
