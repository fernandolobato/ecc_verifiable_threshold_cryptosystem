# Verifiable (t, n) threshold signature scheme based on elliptic curve.


Minimalistic pythonic implementation of a [Verifiable (t, n) threshold signature scheme based on elliptic curve
](https://link.springer.com/article/10.1007/BF02828641).

This implementation serves as a proof of concept. DO NOT TRY TO USE THIS FOR ANY REAL USE CASE. THIS HAS NOT BEEN TESTED EXTERNALLY.


## Dependencies
This is a pythonic implementation using a python [ECDSA](https://github.com/warner/python-ecdsa) cryptographic python library. Python 3.5 is required to run this. Other versions of python haven't been tested but it might work. ECDSA library is compatible with most version of python. Be sure to have python included in yout path. 

The only thing required to run this is argparse for the script that can generate, encrypt and decrypt.

```bash
$ pip install argparse
```


## USAGE

#### Generate a threshold key to encrypt and decrypt messages:

```bash
    $ ./threshold.py --tshares [numShares] --nShares [numShares] --folder ./data
```
Generates the parameters for having a (t, n) threshold cryptosystem where t out of n can reconstruct the original private key.

This script generates a folder and saves the following:
- Public parameters file to verify a secret share is valid.
- Public ECC key file for anybody to encrypt a message.
- Secrets file with all the n shares that can reconstruct file.
- Individual files where each on contains one secret for distribution.

#### Reconstruct a threshold key from sub secrets:
```bash
./threshold.py --file ./data/secret.txt --t 10
```
Should give private key:
```bash
Reconstructed private key: 114512418293542646387878769035889844004884287243204154488848244878157937612245
```
Secretes.txt must be a file with all the t subshares on each line.

#### Encrypt using a threshold key
This is standard ECC encryption. Encrypts a message using a given public key.

```bash
./threshold.py --pkfile ./data/public.csv  --msg "Secret" --outfile ./c.txt
```


#### Decrypt using a reconstructed key

```bash
./threshold.py --decrypt 114512418293542646387878769035889844004884287243204154488848244878157937612245 --infile ./c.txt
```

## Test

    python setup.py test

## Stuff used to make this:

 * [ECDSA](https://github.com/warner/python-ecdsa) ECDSA cryptography python library. 


------

# License

MIT License
