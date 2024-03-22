from Cryptodome.PublicKey import RSA
import sys


def generate_keys(private_key_save_path: str, public_key_save_path: str, pin: str) -> None:
    RSA_ITERATIONS: int = 21000     # Recommended value
    SALT_SIZE = 8
    BLOCK_SIZE = 8
    KEY_LENGTH = 4096

    key = RSA.generate(KEY_LENGTH)
    with open(private_key_save_path + "/private_key.pem", "wb") as f:
        # Creates private key, that is encrypted with 'pin' password. Uses PKCS#8 serialization standard, which supports
        # encryption. Uses SHA512 hashing and AES256 with Cipher Block Chaining encrypting algorithms. To slow down
        # brute attacks, hash algorithm is repeated 'RSA_ITERATIONS' times.
        protection_settings: dict = {
            'iteration_count': RSA_ITERATIONS,
            'salt_size': SALT_SIZE,
            'block_size': BLOCK_SIZE
        }
        data = key.export_key(passphrase=pin,
                              pkcs=8,
                              protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                              prot_params=protection_settings)
        f.write(data)

    with open(public_key_save_path + "/public_key.pem", "wb") as f:
        data = key.public_key().export_key()
        f.write(data)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise Exception("Expected arguments: \n- Private key path\n- Public key path\n- PIN value")

    private_key_path: str = sys.argv[1]
    public_key_path: str = sys.argv[2]
    pin: str = sys.argv[3]
    generate_keys(private_key_path, public_key_path, pin)
