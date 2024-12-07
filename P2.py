#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep  7 17:44:43 2021
@author: christer

modified on Tue Sep 24 2024
by: Jonathan Zulu & David Fartacek

ref: 
1. The cryptography library documentation: https://cryptography.io/en/latest/
2. Python documentation for socket programming: https://docs.python.org/3/library/socket.html
"""
# P2 acts as a server due to the while loop, listening to a dedicated port.
# In this lab, P2 will both initiate sending messages and respond to messages 
 

import socket
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

print("P2: Starting...")

localIP = "127.0.0.1"
localPort = 3010
bufferSize = 1024

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((localIP, localPort))

print("P2: UDP server up and listening")

# Receive public key and hash from P1
print("P2: Waiting for public key from P1...")
bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
message = bytesAddressPair[0]
address = bytesAddressPair[1]

#print("P2: Public key received.",message)

public_key_bytes, received_hash = message.split(b'|')
calculated_hash = hashlib.sha256(public_key_bytes).hexdigest()

#print("P2: Calculated hash:", calculated_hash)
#print("P2: Received hash:", received_hash)

if calculated_hash == received_hash.decode():
    print("P2: Public key integrity verified")
else:
    print("P2: Public key integrity check failed")
    exit(1)

# Deserialize public key
public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend()
)

#print("P2: Public key deserialized.",public_key)

print("P2: Generating symmetric key...")
# Generate symmetric key
sym_key = os.urandom(32)  # 256-bit key

print("P2: Encrypting symmetric key with P1's public key...")
# Encrypt symmetric key with public key
encrypted_sym_key = public_key.encrypt(
    sym_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#print("P2: Encrypted symmetric key:",encrypted_sym_key)
print("P2: Sending encrypted symmetric key to P1...")
# Send encrypted symmetric key to P1
UDPServerSocket.sendto(encrypted_sym_key, address)

# Set up AES cipher
cipher = Cipher(algorithms.AES(sym_key), modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()
#print("P2: AES cipher set up.")

print("P2: Waiting for encrypted message from P1...")
# Receive encrypted message from P1
encrypted_message = UDPServerSocket.recvfrom(bufferSize)[0]
decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
print(f"P2: Decrypted message from P1: {decrypted_message.rstrip().decode()}")
print("P2: Sending encrypted response to P1...")
# Send encrypted response to P1
response = b"Hello P1, I received your secret message!"
padded_response = response + b" " * (16 - (len(response) % 16))
encrypted_response = encryptor.update(padded_response) + encryptor.finalize()
#print("P2: Encrypted response:",encrypted_response)
UDPServerSocket.sendto(encrypted_response, address)

print("P2: Communication complete.")