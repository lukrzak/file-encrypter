from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


def encrypt_file(file_path: str, public_key_path: str) -> None:
    with open(public_key_path, "rb") as f:
        public_key = RSA.importKey(f.read())

    cipher = PKCS1_OAEP.new(public_key)
    with open(file_path, "rb") as f:
        content = f.read()

    encrypted_content = cipher.encrypt(content)
    with open("output.txt", "wb") as f:
        f.write(encrypted_content)


encrypt_file("D:\\semVI\\file-encrypter\\src\\texxt.txt", "D:\\semVI\\file-encrypter\\src\\public_key.pem")


def decrypt_file(file_path: str, private_key_path: str, pin: str) -> None:
    with open(private_key_path, "rb") as f:
        private_key = RSA.importKey(f.read(), pin)

    cipher = PKCS1_OAEP.new(private_key)
    with open(file_path, "rb") as f:
        content = f.read()

    decrypted_content = cipher.decrypt(content)
    with open("output_de.txt", "wb") as f:
        f.write(decrypted_content)


decrypt_file("D:\\semVI\\file-encrypter\\src\\output.txt", "D:\\semVI\\file-encrypter\\src\\private_key.pem", "1234")
