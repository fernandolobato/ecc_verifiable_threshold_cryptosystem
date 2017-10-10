#
#
#
#
import hashlib
import math
import random

from ecdsa.util import randrange
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point


def secret_split():
    pass

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

                mult *= (h / (h - j))

        recon_key += sub_secret_share[j - 1] * int(mult)

    return recon_key % SECP256k1.order


def encrypt():
    pass

master_private_key = randrange(SECP256k1.order)
master_public_key = master_private_key * SECP256k1.generator

t = 10
n = 100

coef = [master_private_key] + [randrange(SECP256k1.order) for i in range(1, t)]

f = lambda x: sum([ coef[i] * pow(x, i) for i in range(t)]) % SECP256k1.order

secret_share = [ f(i) for i in range(1, n + 1)]

F = [ coef[j] * SECP256k1.generator for j in range(t) ]

# for i in range(n):
#     assert(verify_secret_share(secret_share[i],i,F))

r = secret_share[:]
random.shuffle(r)

r_key = reconstruct_key(secret_share[:t], t)

print(r_key == master_private_key)




