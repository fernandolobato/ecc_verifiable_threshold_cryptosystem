#! /usr/bin/env python
import os
import argparse

from ecdsa.ellipticcurve import Point
from ecdsa.ecdsa import curve_secp256k1
import threshold_library as th


def reconstruct(file_path, t):
    return th.reconstruct_key([ int(s) for s in open(file_path, 'r').readlines()[0].split(',')], t)

def main():
    parser = argparse.ArgumentParser(description='Threshold Cryptosystem Tool')

    # RECONSTRUCT KEYS
    reconstruct_group = parser.add_argument_group(title='Reconstruct Key')
    
    reconstruct_group.add_argument(
        '--file',
        default=None,
        type=str,
        help='Path to comma separated file with secrets.')

    reconstruct_group.add_argument(
        '--t',
        default=None,
        type=int,
        help='Number of subshares to reconstruct')
    # RECONSTRUCT KEYS


    # ENCRYPT
    encrypt_group = parser.add_argument_group(title='Encrypt Message')

    encrypt_group.add_argument(
        '--pkfile',
        default=None,
        help='File containing public key')

    encrypt_group.add_argument(
        '--msg',
        default=None,
        type=int,
        help='Message to encrypt')

    encrypt_group.add_argument(
        '--outfile',
        default='./ciphertext.txt',
        help='File to output message')
    
    # ENCRYPT


    # GENERATE PARAMETERS

    generate_group = parser.add_argument_group(title='Generate and save threshold parameters')

    generate_group.add_argument(
        '--tshares',
        default=None,
        type=int,
        help='Number of reconstructable shares')

    generate_group.add_argument(
        '--nshares',
        default=None,
        type=int,
        help='Total number of shares')

    generate_group.add_argument(
        '--folder',
        default='./threshold_data/',
        help='Folder to save data on')



    args = parser.parse_args()

    # Reconstruct Key
    if args.file and args.t:
        print('Reconstructed private key: {}'.format(reconstruct(args.file, args.t)))


    #Encrypt
    if args.pkfile and args.msg and args.outfile:
        p =  open(args.pkfile).readlines()[0].split(',')
        p_k = Point(curve_secp256k1, int(p[0]), int(p[1][:-1]))

        c = th.encrypt(p_k, args.msg)

        l = '{},{},{}'.format(c[0].x(), c[0].y(), c[1])
        open(args.outfile, 'w').write(l)

    #Generate
    if args.tshares and args.nshares and args.folder:
        params = th.generate_threshold_parameters(args.tshares, args.nshares)

        th.save_params_file(args.tshares, args.nshares, params, args.folder)


if __name__ == '__main__':
    main()