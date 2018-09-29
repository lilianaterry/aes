#!/usr/bin/env python3
import argparse
import aes_runner

def verify_inputfile(inputfile):
    # Check to see if input file exists
    pass

if __name__ == '__main__':
    parser=argparse.ArgumentParser()

    parser.add_argument('--keysize', required=True, help='The size of the key', type=int, choices=[128, 192, 256])
    parser.add_argument('--keyfile', required=True, help='The path to the key')
    parser.add_argument('--inputfile', required=True, help='The file to encrypt or decrypt')
    parser.add_argument('--outputfile', required=True, help='The destination file path for the output')
    parser.add_argument('--mode', required=True, help='Whether to encrypt or decrypt the file', choices=['encrypt', 'decrypt'])
    parser.add_argument('--operation', required=False, help="ECB (Electronic Code Block) mode will independently encrypt each \
    block of input. CBC (Code Block Chaining) mode will use the previous block as part of the encryption process, removing patterns \
    that can be found in plaintext and increasing security.", choices=['ecb', 'cbc'], default="ecb")

    args=parser.parse_args()

    aes_runner.run(args.keyfile, args.keysize, args.inputfile, args.outputfile, args.mode, args.operation)
