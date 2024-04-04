import unittest
import os
from src.file_cipher import cipher_file
from src.rsa_generator import generate_keys


class TestFileCipher(unittest.TestCase):
    def test_cipher_with_output_file(self):
        WORKDIR: str = os.getcwd()
        PIN_VALUE: str = "1234"
        TEST_CONTENT: str = "ABCDE"
        TEST_FILE: str = "test.txt"
        PUBLIC_KEY_NAME = "pub.pem"
        PRIVATE_KEY_NAME = "priv.pem"
        CERTIFICATE_NAME = "cert.pem"
        OUTPUT_FILENAME = "output.txt"
        generate_keys(WORKDIR + "\\" + PRIVATE_KEY_NAME,
                      WORKDIR + "\\" + PUBLIC_KEY_NAME,
                      PIN_VALUE,
                      WORKDIR + "\\" + CERTIFICATE_NAME
                      )

        f = open(WORKDIR + "\\" + TEST_FILE, "w")
        f.write(TEST_CONTENT)
        f.close()

        cipher_file(file_path=WORKDIR + "\\" + TEST_FILE,
                    key_path=WORKDIR + "\\" + PUBLIC_KEY_NAME,
                    mode="encrypt",
                    output_mode="file",
                    output_path=WORKDIR + "\\" + OUTPUT_FILENAME
                    )
        cipher_file(file_path=WORKDIR + "\\" + OUTPUT_FILENAME,
                    key_path=WORKDIR + "\\" + PRIVATE_KEY_NAME,
                    pin=PIN_VALUE,
                    mode="decrypt",
                    output_mode="file",
                    output_path=WORKDIR + "\\" + OUTPUT_FILENAME
                    )

        assert os.path.exists(WORKDIR + "\\" + OUTPUT_FILENAME)
        assert open(WORKDIR + "\\" + OUTPUT_FILENAME).read() == TEST_CONTENT
        with self.assertRaises(Exception):
            cipher_file("", "", "wrong_mode")
            cipher_file("", "", "encrypt", output_mode="wrong_mode")

        # Cleanup
        os.remove(WORKDIR + "\\" + OUTPUT_FILENAME)
        os.remove(WORKDIR + "\\" + PRIVATE_KEY_NAME)
        os.remove(WORKDIR + "\\" + PUBLIC_KEY_NAME)
        os.remove(WORKDIR + "\\" + TEST_FILE)

    def test_cipher_with_return_value(self):
        WORKDIR: str = os.getcwd()
        PIN_VALUE: str = "1234"
        TEST_CONTENT: str = "ABCDE"
        TEST_FILE: str = "test.txt"
        PUBLIC_KEY_NAME = "pub.pem"
        PRIVATE_KEY_NAME = "priv.pem"
        CERTIFICATE_NAME = "cert.pem"
        OUTPUT_FILENAME = "output.txt"
        generate_keys(WORKDIR + "\\" + PRIVATE_KEY_NAME,
                      WORKDIR + "\\" + PUBLIC_KEY_NAME,
                      PIN_VALUE,
                      WORKDIR + "\\" + CERTIFICATE_NAME
                      )

        f = open(WORKDIR + "\\" + TEST_FILE, "w")
        f.write(TEST_CONTENT)
        f.close()

        cipher_file(file_path=WORKDIR + "\\" + TEST_FILE,
                    key_path=WORKDIR + "\\" + PUBLIC_KEY_NAME,
                    mode="encrypt",
                    output_mode="file",
                    output_path=WORKDIR + "\\" + OUTPUT_FILENAME
                    )
        decrypt_result: bytes = cipher_file(file_path=WORKDIR + "\\" + OUTPUT_FILENAME,
                                            key_path=WORKDIR + "\\" + PRIVATE_KEY_NAME,
                                            pin=PIN_VALUE,
                                            mode="decrypt"
                                            )
        assert decrypt_result.decode() == TEST_CONTENT

        # Cleanup
        os.remove(WORKDIR + "\\" + OUTPUT_FILENAME)
        os.remove(WORKDIR + "\\" + PRIVATE_KEY_NAME)
        os.remove(WORKDIR + "\\" + PUBLIC_KEY_NAME)
        os.remove(WORKDIR + "\\" + TEST_FILE)


if __name__ == '__main__':
    unittest.main()
