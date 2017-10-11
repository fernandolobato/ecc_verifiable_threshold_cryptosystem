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

    for j in range(1, len(F)):
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


def decrypt(sec_key, cipher):
    """
    """
    (P, c) = cipher
    H = sec_key * P

    message = c * pow(H.y(), -1)

    return round(message)


def generate_key():
    """
    """
    return randrange(SECP256k1.order)


def generate_threshold_parameters(t, n):
    """
    """
    s_key = generate_key()
    p_key = s_key * SECP256k1.generator
    
    (s, F) = secret_split(s_key, t, n)

    return (s_key, p_key, s, F) 


