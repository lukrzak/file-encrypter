import math
import tkinter as tk

from customtkinter import *
import customtkinter
from rsa_generator import generate_keys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509 import load_der_x509_certificate
from lxml import etree
import datetime
import base64
import os


SYMMETRIC_KEY_LENGTH: int = 256
KEY_ITERATIONS: int = 21_000     # Recommended value
SALT: bytes = b'bsk-project'
MAX_ENC_BLOCK_SIZE = 512 - 11   # 512 bytes (from the key size) - 11 for PKCS padding
MAX_DEC_BLOCK_SIZE = 512        # 512 bytes from the key

def cipher_file(file_path: str, key_path: str, mode: str, pin: str = None, output_path: str = None,
                output_mode: str = "value", progress_bar: CTkProgressBar = None):
    if mode == "encrypt":
        return encrypt_file(file_path, key_path, output_path, output_mode, progress_bar)
    elif mode == "decrypt":
        return decrypt_key(file_path, key_path, pin, output_path, output_mode, progress_bar)
    else:
        raise Exception("Unknown mode. Allowed values are 'encrypt' or 'decrypt'")


def encrypt_file(file_path: str, public_key_path: str, output_path: str, output_mode: str = "value", 
                 progress_bar: CTkProgressBar = None):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    with open(file_path, "rb") as f:
        content = f.read()

    encryption_status_finish_value = math.ceil(len(content) / MAX_ENC_BLOCK_SIZE)
    data_packages = [content[i * MAX_ENC_BLOCK_SIZE: (i + 1) * MAX_ENC_BLOCK_SIZE] for i in range(encryption_status_finish_value)]
    encrypted_file_content = b''
    progress_val = 1/encryption_status_finish_value
    step_val = 0
    for package in data_packages:
        encrypted_text = public_key.encrypt(
            package,
            padding.PKCS1v15()
        )
        encrypted_file_content += encrypted_text
        step_val = step_val + progress_val
        progress_bar.set(step_val)
        progress_bar.update_idletasks()

    return get_content(output_mode, encrypted_file_content, output_path)


def decrypt_key(file_path: str, private_key_path: str, pin: str, output_path: str, output_mode: str = "value",
                progress_bar: CTkProgressBar = None):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=load_pin_hash(pin)
        )
    with open(file_path, "rb") as f:
        content = f.read()

    decryption_status_finish_value = math.ceil(len(content) / MAX_DEC_BLOCK_SIZE)
    data_packages = [content[i * MAX_DEC_BLOCK_SIZE: (i + 1) * MAX_DEC_BLOCK_SIZE] for i in range(decryption_status_finish_value)]
    decrypted_file_content = b''

    progress_val = 1/decryption_status_finish_value
    step_val = 0
    for package in data_packages:
        decrypted_text = private_key.decrypt(
            package,
            padding.PKCS1v15()
        )
        step_val = step_val + progress_val
        decrypted_file_content += decrypted_text
        progress_bar.set(step_val)
        progress_bar.update_idletasks()

    return get_content(output_mode, decrypted_file_content, output_path)


def load_pin_hash(pin: str):
    sym_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_LENGTH,
        salt=SALT,
        iterations=KEY_ITERATIONS
    )
    symmetric_key = sym_key.derive(pin.encode())

    return symmetric_key


def get_content(output_mode: str, content: bytes, output_path: str):
    if output_mode == "value":
        return content
    elif output_mode == "file":
        with open(output_path, "wb") as f:
            f.write(content)
        return f"Saved to file {output_path}"
    else:
        raise Exception("Unknown output mode. Allowed values are 'file' or 'value'")


def generate_file_signature(file_path: str, private_key_path: str, certificate_path: str, pin: str, signature_output_path: str):
    XADES_TEPMLATE_PATH: str = "src/xades_template.xml"
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=load_pin_hash(pin)
        )
    with open(file_path, "rb") as f:
        content_to_sign = f.read()

    signature_value: str = get_file_signature(private_key, content_to_sign)
    file_hash: str = get_file_hash(content_to_sign)
    certificate: str = get_certificate_value(certificate_path)

    with open(XADES_TEPMLATE_PATH, "r") as f:
        root = etree.fromstring(f.read())
    replace_xades_template_placeholders(root, signature_value, file_hash, certificate, file_path)

    with open(signature_output_path, "wb") as f:
        f.write(etree.tostring(root, encoding="utf-8"))


def get_file_signature(private_key, content: bytes):
    signature = private_key.sign(
        content,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode('utf-8')


def get_file_hash(content: bytes):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(content)
    hash_value = hasher.finalize()

    return base64.b64encode(hash_value).decode('utf-8')


def get_certificate_value(certificate_path: str):
    with open(certificate_path, "rb") as f:
        cert = f.read()

    return base64.b64encode(cert).decode('utf-8')


def replace_xades_template_placeholders(root, signature_value: str, file_hash: str, certificate: str, file_path: str):
    signature_value_element = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
    digest_element = root.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestValue")
    certificate_element = root.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    signature_timestamp_element = root.find(".//SignedSignatureProperties")
    object_metadata_element = root.find(".//SignedDataObjectProperties")

    file_size = os.path.getsize(file_path)
    modification_time = os.path.getmtime(file_path)
    file_format = os.path.splitext(file_path)[1]

    signature_value_element.text = signature_value
    digest_element.text = file_hash
    certificate_element.text = certificate
    signature_timestamp_element.text = str(datetime.datetime.utcnow())
    object_metadata_element.text = f"{file_size}B,{modification_time},{file_format}"


def verify_signature(file_path: str, xades_signature_path: str):
    with open(xades_signature_path, "r") as f:
        root = etree.fromstring(f.read())
    with open(file_path, "rb") as f:
        content = f.read()

    signature = base64.b64decode(root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text.encode())
    # TODO compare hash result with digest value
    digest = base64.b64decode(root.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestValue").text.encode())
    certificate_value = base64.b64decode(root.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate").text.encode())
    certificate = load_der_x509_certificate(certificate_value)
    public_key = certificate.public_key()

    try:
        public_key.verify(
            signature,
            content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
