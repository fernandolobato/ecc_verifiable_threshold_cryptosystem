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
import os

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.ecdsa import curve_secp256k1


def secret_split(secret, t, n, G=SECP256k1.generator, O=SECP256k1.order):
    """ 
        Splits a secret into n shares out which t can reconstruct the key.

        PARAMS
        ------
            secret: (int) Secret to be split.

            t: (int) Size of the sub set that should be able to reconstruct key.

            n: (int) Number of shares into which the secret is split.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
            
            O: (int) Order of elliptic curve

        RETURNS
        -------
            secret_share: (list) A list containing the splits of the secret.

            F: (list) list of public parameters used to generate secret_share.
                coeficients used multiplied by the EC generator to make them public.

    """
    assert(n >= t)

    coef = [secret] + [randrange(SECP256k1.order) for i in range(1, t)]

    f = lambda x: sum([ coef[i] * pow(x, i) for i in range(t)]) % O

    secret_share = list(map(f, list(range(1, n + 1))))

    F = [ coef[j] * G for j in range(t) ]
    
    return (secret_share, F)    


def verify_secret_share(secret_share, i, F, G=SECP256k1.generator):
    """ 
        Verifies that a specific share of a set of secret shares is
        valid against a list of public parameters used to generate it.
    
        PARAMS
        ------
            secret_share: (int) specific share to be verified.
            
            i: (int) index of the secrete instance in the share

            F: (list) set of public parameters with which the share
                was generated.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
        
        RETURNS
        -------
            boolean value indicating if specific share is valid.

    """
    verify = F[0]

    for j in range(1, len(F)):
        verify += pow(i+1, j) * F[j]

    return verify == secret_share * G


def reconstruct_key(sub_secret_share, t, G=SECP256k1.order):
    """ 
        Reconstructs a secret from a share of sub secrets. Requires
        a subset of size t. The sub secret share is the split of the
        original split.

        PARAMS
        ------
            sub_secret_share: (int) sub set of secrets that can reconstruct secret.
            
            t: (int) size of sub set that can reconstruct secret.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
        
        RETURNS
        -------
            reconstructed key.

    """
    assert(len(sub_secret_share) >= t)
    recon_key = 0
    
    for j in range(1, t + 1):
        mult = 1
        
        for h in range(1, t + 1):
            if h != j:
                mult *= ( h / (h - j))

        recon_key += sub_secret_share[j - 1] * int(mult)

    return recon_key % G


def encrypt(pub_key, message, G=SECP256k1.generator, O=SECP256k1.order):
    """ Encrypts a message with an ECC threshold public key.
        Standard ECC encryption.
        
        PARAMS
        ------
            pub_key: (int) public key with which to encrypt message.

            message: (int) message to be encrypted.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
            
            O: (int) Order of elliptic curve
        
        RETURNS
        -------
            (P, c) touple with encrypted message.
    """ 
    k = randrange(O)
    
    P = k * G
    H = k * pub_key

    c = message * H.y()

    return (P, c)


def decrypt(sec_key, cipher):
    """ Descrypts a ciphertext encrypted with the corresponding public key
        to the private key being provided.
        
        PARAMS
        ------
            sec_key: (int) secret key corresponding to the public key used to
            encrypt message.

            cipher: (ecdsa.ellipticcurve.Point, int) encrypted message.

        RETURNS
        -------
            message: (int) original message. 

    """
    (P, c) = cipher
    H = sec_key * P

    message = c * pow(H.y(), -1)

    return round(message)


def generate_key(order=SECP256k1.order):
    """
    """
    return randrange(order)


def generate_threshold_parameters(t, n):
    """
    """
    s_key = generate_key()
    p_key = s_key * SECP256k1.generator
    
    (s, F) = secret_split(s_key, t, n)

    return (s_key, p_key, s, F) 


def save_params_file(t, n, directory='./data', public_filename='public.csv'):
    """
    """
    if not os.path.exists(directory):
        os.makedirs(directory)

    (s_k, p_k, s, F) = generate_threshold_parameters(t, n)


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

    s_k = reconstruct_key(s, len(F))
    
    return (s_k, p_k, s, F)
