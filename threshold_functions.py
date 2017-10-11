import os

import threshold_cryptosystem as threshold

from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1


def save_params_file(t, n, directory='./data', public_filename='public.csv'):
    """
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

    (s_k, p_k, s, F) = threshold.generate_threshold_parameters(t, n)


    public_file = open(os.path.join(directory, public_filename), 'w')

    stringify_point = lambda p: '{},{}\n'.format(p.x(), p.y())

    public_file.write(stringify_point(p_k))

    public_coeficients = ''.join([ stringify_point(p) for p in F])
    public_file.write(public_coeficients)

    for i in range(len(s)):
        secret_filename = 'share_{}.txt'.format(i+1)
        secret_file = open(os.path.join(directory, secret_filename), 'w')

        secret_file.write('{}'.format(s[i]))

    return (s_k, p_k, s, F)


def load_params_file(directory='./data', public_filename='public.csv'):
    """
    """
    public_file = open(os.path.join(directory, public_filename), 'r')

    data = public_file.readlines()

    p_k = None
    F = [None] * (len(data) - 1)

    for i, point in enumerate(data):
        p = point.split(',')

        if i == 0:
            p_k = Point(curve_secp256k1, int(p[0]), int(p[1][:-1]))
        else:
            F[i - 1] = Point(curve_secp256k1, int(p[0]), int(p[1][:-1]))
    
    i = 1
    s = []
    secret_filename = 'share_{}.txt'.format(i)

    while(os.path.isfile(os.path.join(directory, secret_filename))):
        secret_file = open(os.path.join(directory, secret_filename), 'r')
        s.append(int(secret_file.readlines()[0]))

        i += 1
        secret_filename = 'share_{}.txt'.format(i)

    s_k = threshold.reconstruct_key(s, len(F))
    
    return (s_k, p_k, s, F)


def main():
    a = save_params_file(10, 30)
    b = load_params_file()
    print(a == b)

if __name__ == '__main__':
    main()