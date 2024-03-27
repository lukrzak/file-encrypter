import unittest
import os
from src.rsa_generator import generate_keys


class TestKeyGeneration(unittest.TestCase):
    def test_creating_keys(self):
        KEY_PATH: str = os.getcwd()
        PUBLIC_KEY_NAME: str = "public_key.pem"
        PRIVATE_KEY_NAME: str = "private_key.pem"
        PIN: str = "1234"

        generate_keys(KEY_PATH + "\\" + PRIVATE_KEY_NAME, KEY_PATH + "\\" + PUBLIC_KEY_NAME, PIN)

        self.assertTrue(os.path.exists(KEY_PATH + "\\" + PUBLIC_KEY_NAME))
        self.assertTrue(os.path.exists(KEY_PATH + "\\" + PRIVATE_KEY_NAME))

        # Cleanup
        os.remove(KEY_PATH + "\\" + PUBLIC_KEY_NAME)
        os.remove(KEY_PATH + "\\" + PRIVATE_KEY_NAME)


if __name__ == '__main__':
    unittest.main()
