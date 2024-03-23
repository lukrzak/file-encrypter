import unittest
import os
from src.rsa_generator import generate_keys


class TestKeyGeneration(unittest.TestCase):
    def test_creating_keys(self):
        PUBLIC_KEY_PATH = "D:/"
        PRIVATE_KEY_PATH = "D:/"
        PUBLIC_KEY_NAME = "public_key.pem"
        PRIVATE_KEY_NAME = "private_key.pem"
        PIN = "1234"

        generate_keys(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, PIN)

        self.assertTrue(os.path.exists(PUBLIC_KEY_PATH + PUBLIC_KEY_NAME))
        self.assertTrue(os.path.exists(PRIVATE_KEY_PATH + PRIVATE_KEY_NAME))

        # Cleanup
        os.remove(PUBLIC_KEY_PATH + PUBLIC_KEY_NAME)
        os.remove(PRIVATE_KEY_PATH + PRIVATE_KEY_NAME)


if __name__ == '__main__':
    unittest.main()
