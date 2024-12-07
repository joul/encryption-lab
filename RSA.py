#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep  7 17:44:43 2021
@author: christer

modified on Tue Sep 24 2024
by: Jonathan Zulu & David Fartacek

ref: 
The cryptography library documentation: https://cryptography.io/en/latest/
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Methods for encryption/decryption

def simple_rsa_encrypt(m, publickey):
    numbers = publickey.public_numbers()
    return pow(m, numbers.e, numbers.n)

def simple_rsa_decrypt(c, privatekey):
    numbers = privatekey.private_numbers()
    return pow(c, numbers.d, numbers.public_numbers.n)

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

# We start by generatin the keys, the private key is kept secret
# and the publi key is given to peers communicated with.

# Generate a private key with different key sizes.
key_sizes = [1024, 2048, 3072, 4096]

for key_size in key_sizes:
    print(f"\nGenerating keys with key size: {key_size} bits")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(f"Private key length: {len(private_key_bytes)} bytes")
    print(f"Public key length: {len(public_key_bytes)} bytes")

# THIS IS JUST FOR TRAINING (DO NOT USE THIS FOR REAL CRYPTOGRAPHY)

message = input("\nPlaintext: ").encode()

# Now let's encrypt the message using the publi key
message_as_int = bytes_to_int(message)
cipher_as_int = simple_rsa_encrypt(message_as_int, public_key)
cipher = int_to_bytes(cipher_as_int)
print("The encrypter message looks like this :", cipher)

#Let's see if we can get the text back
message_as_int = simple_rsa_decrypt(cipher_as_int, private_key)
message = int_to_bytes(message_as_int)
print("\nDecrypted messsage: {}\n".format(message))