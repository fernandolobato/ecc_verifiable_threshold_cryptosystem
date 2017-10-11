import threshold_cryptosystem as threshold

from ecdsa.curves import SECP256k1


def generate_threshold(t, n):
    """
    """
    s_key = threshold.generate_key()
    p_key = s_key * SECP256k1.generator
    
    (s, F) = threshold.secret_split(s_key, t, n)

    return (s_key, p_key, s, F)


def test_encryption_decryption(message, t, n):
    """
    """
    (s_key, p_key, s, F) = generate_threshold(t, n)

    r_key = threshold.reconstruct_key(s, t)

    cipher = threshold.encrypt(p_key, message)
    _message = threshold.decrypt(r_key, cipher)

    assert(message == _message)


def test_secret_shares(t, n):
    """
    """
    (s_key, p_key, s, F) = generate_threshold(t, n)

    for i in range(n):
        assert(threshold.verify_secret_share(s[i], i, F))

def test_key_reconstruction(t, n):
    """
    """
    (s_key, p_key, s, F) = generate_threshold(t, n)
    r_key = threshold.reconstruct_key(s, t)
    assert(r_key == s_key)

def main():
    message = 55555
    t = 10
    n = 25

    test_encryption_decryption(message, t, n)
    test_secret_shares(t, n)
    test_key_reconstruction(t, n)

if __name__ == '__main__':
    main()