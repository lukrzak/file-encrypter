import unittest
import os
from src.file_cipher import cipher_file
from src.rsa_generator import generate_keys


class TestFileCipher(unittest.TestCase):
    def test_cipher_with_output_file(self):
        WORKDIR_PATH: str = os.getcwd()
        PIN_VALUE: str = "1234"
        TEST_CONTENT: str = "ABCDE"
        TEST_FILE: str = "test.txt"
        PUBLIC_KEY_NAME = "pub.pem"
        PRIVATE_KEY_NAME = "priv.pem"
        OUTPUT_FILENAME = "output.txt"
        generate_keys(WORKDIR_PATH + "\\" + PRIVATE_KEY_NAME, WORKDIR_PATH + "\\" + PUBLIC_KEY_NAME, PIN_VALUE)
        f = open(WORKDIR_PATH + "\\" + TEST_FILE, "w")
        f.write(TEST_CONTENT)
        f.close()

        cipher_file(file_path=WORKDIR_PATH + "\\" + TEST_FILE,
                    key_path=WORKDIR_PATH + "\\" + PUBLIC_KEY_NAME,
                    mode="encrypt",
                    output_mode="file",
                    output_file=WORKDIR_PATH + "\\" + OUTPUT_FILENAME
                    )
        cipher_file(file_path=WORKDIR_PATH + "\\" + OUTPUT_FILENAME,
                    key_path=WORKDIR_PATH + "\\" + PRIVATE_KEY_NAME,
                    pin=PIN_VALUE,
                    mode="decrypt",
                    output_mode="file",
                    output_file=WORKDIR_PATH + "\\" + OUTPUT_FILENAME
                    )

        assert os.path.exists(WORKDIR_PATH + "\\" + OUTPUT_FILENAME)
        assert open(WORKDIR_PATH + "\\" + OUTPUT_FILENAME).read() == TEST_CONTENT
        with self.assertRaises(Exception):
            cipher_file("", "", "wrong_mode")
            cipher_file("", "", "encrypt", output_mode="wrong_mode")

        # Cleanup
        os.remove(WORKDIR_PATH + "\\" + OUTPUT_FILENAME)
        os.remove(WORKDIR_PATH + "\\" + PRIVATE_KEY_NAME)
        os.remove(WORKDIR_PATH + "\\" + PUBLIC_KEY_NAME)
        os.remove(WORKDIR_PATH + "\\" + TEST_FILE)

    def test_cipher_with_return_value(self):
        WORKDIR_PATH: str = os.getcwd()
        PIN_VALUE: str = "1234"
        TEST_CONTENT: str = "ABCDE"
        TEST_FILE: str = "test.txt"
        PUBLIC_KEY_NAME = "pub.pem"
        PRIVATE_KEY_NAME = "priv.pem"
        OUTPUT_FILENAME = "output.txt"
        generate_keys(WORKDIR_PATH + "\\" + PRIVATE_KEY_NAME, WORKDIR_PATH + "\\" + PUBLIC_KEY_NAME, PIN_VALUE)
        f = open(WORKDIR_PATH + "\\" + TEST_FILE, "w")
        f.write(TEST_CONTENT)
        f.close()

        cipher_file(file_path=WORKDIR_PATH + "\\" + TEST_FILE,
                    key_path=WORKDIR_PATH + "\\" + PUBLIC_KEY_NAME,
                    mode="encrypt",
                    output_mode="file",
                    output_file=WORKDIR_PATH + "\\" + OUTPUT_FILENAME
                    )
        decrypt_result: str = cipher_file(file_path=WORKDIR_PATH + "\\" + OUTPUT_FILENAME,
                                          key_path=WORKDIR_PATH + "\\" + PRIVATE_KEY_NAME,
                                          pin=PIN_VALUE,
                                          mode="decrypt"
                                          )
        assert decrypt_result == TEST_CONTENT

        # Cleanup
        os.remove(WORKDIR_PATH + "\\" + OUTPUT_FILENAME)
        os.remove(WORKDIR_PATH + "\\" + PRIVATE_KEY_NAME)
        os.remove(WORKDIR_PATH + "\\" + PUBLIC_KEY_NAME)
        os.remove(WORKDIR_PATH + "\\" + TEST_FILE)


if __name__ == '__main__':
    unittest.main()
