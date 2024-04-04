from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SYMMETRIC_KEY_LENGTH: int = 256
KEY_ITERATIONS: int = 21_000     # Recommended value
SALT: bytes = b'bsk-project'


def cipher_file(file_path: str, key_path: str, mode: str, pin: str = None, output_path: str = None,
                output_mode: str = "value"):
    if mode == "encrypt":
        return encrypt_file(file_path, key_path, output_path, output_mode)
    elif mode == "decrypt":
        return decrypt_key(file_path, key_path, pin, output_path, output_mode)
    else:
        raise Exception("Unknown mode. Allowed values are 'encrypt' or 'decrypt'")


def encrypt_file(file_path: str, public_key_path: str, output_path: str, output_mode: str = "value"):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    with open(file_path, "rb") as f:
        content = f.read()

    encrypted_text = public_key.encrypt(
        content,
        padding.PKCS1v15()
    )
    return get_content(output_mode, encrypted_text, output_path)


def decrypt_key(file_path: str, private_key_path: str, pin: str, output_path: str, output_mode: str = "value"):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=load_pin_hash(pin)
        )
    with open(file_path, "rb") as f:
        content = f.read()

    decrypted_text = private_key.decrypt(
        content,
        padding.PKCS1v15()
    )
    return get_content(output_mode, decrypted_text, output_path)


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
