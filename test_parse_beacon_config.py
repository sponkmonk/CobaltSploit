#! /usr/bin/python3

import io
import os
import unittest

from parse_beacon_config import cobaltstrikeConfig

from zipfile import ZipFile


def decrypt_sample(zip_path):
    with ZipFile(zip_path) as z:
        for fn in z.namelist():
            return io.BytesIO(z.read(fn, pwd=bytes("infected", "ascii")))


class TestBeaconParsing(unittest.TestCase):
    def test_non_pe_x86(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "samples",
            "13e954be0b0c022c392c956e9a800201a75dab7e288230b835bcdd4a9d68253d.zip",
        )
        f = decrypt_sample(path)
        parser = cobaltstrikeConfig(f)
        conf = parser.parse_encrypted_config()
        self.assertEqual(conf.get("HttpPostUri"), "/submit.php")

    def test_encrypted_x86_64(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "samples",
            "10fd211ba97ddf12aecb1e7931d92c3ba37421c362cb1490e0203c1bd88ec141.zip",
        )
        f = decrypt_sample(path)
        parser = cobaltstrikeConfig(f)
        conf = parser.parse_encrypted_config()
        self.assertEqual(conf.get("PublicKey_MD5"), "d2c8ec15d925e2514714d619022f7cdf")

    def test_encrypted_x86(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "samples",
            "7773169ca4ea81203a550dfebe53f091a8c57a3a5b12386e51c5a05194fef3ff.zip",
        )
        f = decrypt_sample(path)
        parser = cobaltstrikeConfig(f)
        conf = parser.parse_encrypted_config()
        self.assertEqual(conf.get("PublicKey_MD5"), "8ac540617dddcdf575f6dc207abb7344")

    def test_trial_beacon_x86(self):
        path = os.path.join(
            os.path.dirname(__file__),
            "samples",
            "4d1d732125e4d1a3ba0571e0cd892cf8e0dce854387ee405f75df4dcfb0f616b.zip",
        )
        f = decrypt_sample(path)
        parser = cobaltstrikeConfig(f)
        conf = parser.parse_config()
        self.assertIn('header "CGGGGG"', conf.get("HttpGet_Metadata").get("Metadata"))


if __name__ == "__main__":
    unittest.main()
