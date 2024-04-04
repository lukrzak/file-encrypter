from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
import sys
import datetime


SYMMETRIC_KEY_LENGTH: int = 256
KEY_ITERATIONS: int = 21_000        # Recommended value
SALT: bytes = b'bsk-project'


def generate_keys(private_key_save_path: str, public_key_save_path: str, pin: str, certificate_save_path: str) -> None:
    sym_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_LENGTH,
        salt=SALT,
        iterations=KEY_ITERATIONS
    )
    symmetric_key = sym_key.derive(pin.encode())

    private_key = generate_and_save_private_key(symmetric_key, private_key_save_path)
    public_key = generate_and_save_public_key(private_key, public_key_save_path)

    generate_and_save_certificate(private_key, public_key, certificate_save_path)


def generate_and_save_certificate(private_key, public_key, certificate_save_path: str):
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BSK - LN,KP"),
    ])

    certificate = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(subject)\
        .public_key(public_key)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.now())\
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=30))\
        .sign(private_key, hashes.SHA256())

    with open(certificate_save_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))


def generate_and_save_public_key(private_key, public_key_save_path: str):
    public_key = private_key.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(public_key_save_path, "wb") as f:
        f.write(pem_public_key)

    return public_key


def generate_and_save_private_key(symmetric_key, private_key_save_path):
    EXPONENT: int = 65537
    KEY_LENGTH: int = 4_096

    private_key = rsa.generate_private_key(
        public_exponent=EXPONENT,
        key_size=KEY_LENGTH
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(symmetric_key)
    )

    with open(private_key_save_path, "wb") as f:
        f.write(pem_private_key)

    return private_key


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise Exception("Expected arguments: \n- Private key save path\n- Public key save path\n- PIN value")

    private_key_path: str = sys.argv[1]
    public_key_path: str = sys.argv[2]
    pin: str = sys.argv[3]
    certificate_path: str = sys.argv[4]
    generate_keys(private_key_path, public_key_path, pin, certificate_path)
