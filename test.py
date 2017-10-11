from ecdsa.curves import SECP256k1
import threshold_cryptosystem as threshold


def test_encryption_decryption(message, t, n):
    """
    """
    (s_key, p_key, s, F) = threshold.generate_threshold_parameters(t, n)

    r_key = threshold.reconstruct_key(s, t)

    cipher = threshold.encrypt(p_key, message)
    _message = threshold.decrypt(r_key, cipher)

    assert(message == _message)


def test_secret_shares(t, n):
    """
    """
    (s_key, p_key, s, F) = threshold.generate_threshold_parameters(t, n)

    for i in range(n):
        assert(threshold.verify_secret_share(s[i], i, F))

def test_key_reconstruction(t, n):
    """
    """
    (s_key, p_key, s, F) = threshold.generate_threshold_parameters(t, n)
    r_key = threshold.reconstruct_key(s, t)
    assert(r_key == s_key)


def test_file_write_read(t, n):
    """
    """
    a = threshold.save_params_file(t, n)
    b = threshold.load_params_file()
    assert(a[0] == b[0])

def main():
    message = 55555
    t = 10
    n = 25

    test_encryption_decryption(message, t, n)
    test_secret_shares(t, n)
    test_key_reconstruction(t, n)
    test_file_write_read(t, n)

if __name__ == '__main__':
    main()