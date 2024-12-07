#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep  7 17:44:43 2021
@author: christer

modified on Tue Sep 24 2024
by: Jonathan Zulu & David Fartacek

ref: 
1. The cryptography library documentation: https://cryptography.io/en/latest/
2. Python documentation: https://docs.python.org/3/library/socket.html

"""
import os
import socket
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


print("P1: Starting....")

# Generate RSA key pair
print("P1: Generating RSA key pair...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
#print("P1: Private key generated.",private_key)

public_key = private_key.public_key()

# Serialize public key
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
#print("P1: Public key generated.",public_key_bytes)
# Calculate hash of public key
public_key_hash = hashlib.sha256(public_key_bytes).hexdigest()
#print("P1: Public key hash generated.",public_key_hash)
# UDP setup
serverAddressPort = ("127.0.0.1", 3010)
bufferSize = 1024

# Create a UDP socket
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

print("P1: Sending public key and hash to P2...")
# Send public key and hash to P2
message = public_key_bytes + b'|' + public_key_hash.encode()
UDPClientSocket.sendto(message, serverAddressPort)

print("P1: Waiting for encrypted symmetric key from P2...")
# Receive encrypted symmetric key from P2
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
encrypted_sym_key = msgFromServer[0]

print("P1: Decrypting symmetric key...")
#print("P1: Encrypted symmetric key received.",encrypted_sym_key)
# Decrypt symmetric key using private key
sym_key = private_key.decrypt(
    encrypted_sym_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
#print("P1: Symmetric key decrypted.",sym_key)
# Set up AES cipher
cipher = Cipher(algorithms.AES(sym_key), modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()
#print("P1: AES cipher set up.",cipher)
# Get user input for the message
message = input("P1: Enter a message to encrypt and send to P2: ").encode()

print("P1: Encrypting and sending message to P2...")
# Send encrypted message to P2
padded_message = message + b" " * (16 - (len(message) % 16))
encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
UDPClientSocket.sendto(encrypted_message, serverAddressPort)
#print("P1: Message sent to P2.",encrypted_message)

print("P1: Waiting for encrypted response from P2...")
# Receive encrypted response from P2
encrypted_response = UDPClientSocket.recvfrom(bufferSize)[0]
decrypted_response = decryptor.update(encrypted_response) + decryptor.finalize()
print(f"P1: Decrypted response from P2: {decrypted_response.rstrip().decode()}")
#print("P1: Encrypted response from P2.",encrypted_response)

print("P1: Communication complete.")