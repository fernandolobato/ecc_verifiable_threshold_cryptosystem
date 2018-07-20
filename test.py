from ecdsa.curves import SECP256k1
import threshold_library as threshold
from unittest import TestCase


class ThresholdTestCase(TestCase):
    def setUp(self):
        self.message = 55555
        self.t = 10
        self.n = 25

    def test_encryption_decryption(self):
        """ Tests that a message can be encypted and decrypted.
        """
        (s_key, p_key, s, F) = threshold.generate_threshold_parameters(self.t, self.n)

        r_key = threshold.reconstruct_key(s, self.t)

        cipher = threshold.encrypt(p_key, self.message)
        _message = threshold.decrypt(r_key, cipher)
        self.assertEqual(self.message, _message)

    def test_secret_shares(self):
        """ Tests that each generated when splitting the secret is valid.
        """
        (s_key, p_key, s, F) = threshold.generate_threshold_parameters(self.t, self.n)

        for i in range(self.n):
            self.assertTrue(threshold.verify_secret_share(s[i], i, F))

    def test_key_reconstruction(self):
        """ Tests that a secret key can be reconstructed.
        """
        (s_key, p_key, s, F) = threshold.generate_threshold_parameters(self.t, self.n)
        r_key = threshold.reconstruct_key(s, self.t)
        self.assertEqual(r_key, s_key)

    def test_file_write_read(self):
        """ Tests that parameters being generated to file can be
            imported again.
        """
        a = threshold.save_params_file(self.t, self.n)
        b = threshold.load_params_file()
        self.assertEqual(a[0], b[0])

    def test_custom_secret_shares(self):
        (s_k, p_k, s, F) = threshold.load_params_file()
        
        for i in range(len(s)):
            self.assertTrue(threshold.verify_secret_share(s[i], i, F))
