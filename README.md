Symmetric and Asymmetric lab

Initial Setup:
P2.py acts as a server, listening on localhost (127.0.0.1) port 3010
P1.py acts as a client, connecting to P2's address
Key Exchange Process:
   │   P1                                    P2
   ├─ Generates RSA key pair             │
   ├─ Creates public key hash            │
   ├─ Sends public key + hash ─────────► │
   │                                     ├─ Verifies hash
   │                                     ├─ Generates AES symmetric key
   │                                     ├─ Encrypts symmetric key with P1's public key
   │ ◄─────── Sends encrypted key ───────┤
   ├─ Decrypts symmetric key             │
   
Message Exchange:
   │   P1                                    P2
   ├─ Gets user input                    │
   ├─ Encrypts with symmetric key        │
   ├─ Sends encrypted message ─────────► │
   │                                     ├─ Decrypts message
   │                                     ├─ Creates response
   │                                     ├─ Encrypts response
   │ ◄───── Sends encrypted response ────┤
   ├─ Decrypts response                  │
   
Security Features:
Uses RSA for secure key exchange
Uses AES for efficient message encryption
Includes hash verification for public key integrity
Uses OAEP padding for RSA encryption
Uses 256-bit AES keys for symmetric encryption
The system combines asymmetric encryption (RSA) for secure key exchange with symmetric encryption (AES) for efficient message exchange.
