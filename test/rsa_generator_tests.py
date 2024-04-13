import unittest
import os
from src.rsa_generator import generate_keys


class TestKeyGeneration(unittest.TestCase):
    def test_creating_keys(self):
        WORKDIR: str = os.getcwd()
        PUBLIC_KEY_NAME: str = "public_key.pem"
        PRIVATE_KEY_NAME: str = "private_key.pem"
        CERTIFICATE_KEY_NAME: str = "certificate.pem"
        PIN: str = "1234"

        generate_keys(WORKDIR + "\\" + PRIVATE_KEY_NAME,
                      WORKDIR + "\\" + PUBLIC_KEY_NAME, PIN,
                      WORKDIR + "\\" + CERTIFICATE_KEY_NAME
                      )

        self.assertTrue(os.path.exists(WORKDIR + "\\" + PUBLIC_KEY_NAME))
        self.assertTrue(os.path.exists(WORKDIR + "\\" + PRIVATE_KEY_NAME))
        self.assertTrue(os.path.exists(WORKDIR + "\\" + CERTIFICATE_KEY_NAME))

        # Cleanup
        os.remove(WORKDIR + "\\" + PUBLIC_KEY_NAME)
        os.remove(WORKDIR + "\\" + PRIVATE_KEY_NAME)
        os.remove(WORKDIR + "\\" + CERTIFICATE_KEY_NAME)


if __name__ == '__main__':
    unittest.main()
