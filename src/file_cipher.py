from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


def cipher_file(file_path: str, key_path: str, mode: str,
                pin: str = None, output_mode: str = "value", output_file: str = None):
    # Read key and create Cipher object based on the provided key
    with open(key_path, "rb") as f:
        key = RSA.importKey(f.read(), pin)
    cipher = PKCS1_OAEP.new(key)

    # Read file content
    with open(file_path, "rb") as f:
        content = f.read()

    # Prepare and return content based on chosen mode
    cipher_content = get_cipher_content(cipher, content, mode)
    return get_cipher_result(cipher_content, output_mode, output_file, mode)


def get_cipher_content(cipher, content: bytes, mode: str) -> bytes:
    if mode == "encrypt":
        return cipher.encrypt(content)
    elif mode == "decrypt":
        return cipher.decrypt(content)
    else:
        raise Exception("Unknown mode. Allowed values are 'encrypt' or 'decrypt'")


def get_cipher_result(cipher_content: bytes, output_mode: str, output_file: str, mode: str) -> str:
    if output_mode == "value":
        if mode == "decrypt":
            return cipher_content.decode()
        else:
            return "Encoded"
    elif output_mode == "file":
        with open(output_file, "wb") as f:
            f.write(cipher_content)
        return f"Result saved in {output_file}"
    else:
        raise Exception("Unknown output mode. Allowed values are 'file' or 'value'")
