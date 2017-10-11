#! /usr/bin/env python
#
# Provide an implementation of a (t,n) threshold cryptosystem. 
#
# Implementation of cryptographic scheme from:
# 
#
# Written in 2017 by Fernanddo Lobato Meeser and placed in the public domain.

import hashlib
import math
import random

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point


def secret_split(secret, t, n):
    """
    """
    coef = [secret] + [randrange(SECP256k1.order) for i in range(1, t)]

    f = lambda x: sum([ coef[i] * pow(x, i) for i in range(t)]) % SECP256k1.order

    secret_share = [ f(i) for i in range(1, n + 1)]

    F = [ coef[j] * SECP256k1.generator for j in range(t) ]
    
    return (secret_share, F)    


def verify_secret_share(secret_share, i, F, G=SECP256k1.generator):
    """
    """
    verify = F[0]

    for j in range(1, t):
        verify += pow(i+1, j) * F[j]

    return verify == secret_share * SECP256k1.generator


def reconstruct_key(sub_secret_share, t):
    """
    """
    assert(len(sub_secret_share) >= t)
    recon_key = 0
    
    for j in range(1, t + 1):
        mult = 1
        
        for h in range(1, t + 1):
            if h != j:
                mult *= ( h / (h - j))

        recon_key += sub_secret_share[j - 1] * int(mult)

    return recon_key % SECP256k1.order


def encrypt(pub_key, message):
    """
    """ 
    k = randrange(SECP256k1.order)
    
    P = SECP256k1.generator * k
    H = k * pub_key

    c = message * H.y()

    return (P, c)

def decrypt(sec_key, signature):
    """
    """
    (P, c) = signature
    H = sec_key * P

    message = c * pow(H.y(), -1)

    return round(message)


def string_to_int(msg):
    """
    """
    return int(''.join([ str(ord(c)) for c in msg]))

def int_to_string(num):
    """
    """
    num = str(num)
    return ''.join([ chr(int(num[i:i+2])) for i in range(0,len(num),2)])



def main():


    master_private_key = randrange(SECP256k1.order)
    master_public_key = master_private_key * SECP256k1.generator

    t = 10
    n = 20 

    secret_share, F = secret_split(master_private_key, t, n)

    message = 'GERM'

    msg = string_to_int(message)
    print(msg)

    ciphertext = encrypt(master_public_key, msg)
    msg_2 = decrypt(master_private_key, ciphertext)  

    print(msg_2)

# for i in range(n):
#     assert(verify_secret_share(secret_share[i],i,F))



# for i in range(10):
#     msg = random.randint(1, 1000)
#     ciphertext = encrypt(master_public_key, msg)
#     msg_2 = decrypt(master_private_key, ciphertext)
#     assert(msg_2 == msg)

# print(string_to_int('abc'))


# r_key = reconstruct_key(secret_share, t)

# print(r_key == master_private_key)


if __name__ == '__main__':
    main()


