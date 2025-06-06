# Secure Chat Application (NetSec3)

This repository contains a simple example of a secure chat system.
It demonstrates Elliptic Curve Diffie-Hellman (ECDH) key exchange,
AES-GCM encryption and a basic challenge‑response authentication
scheme implemented in Python.

## Components

- **`chat_server.py`**: UDP server handling user signups,
  challenge‑response authentication and relaying messages between
  clients.
- **`chat_client.py`**: Console client that connects to the server,
  performs an ECDH key exchange and allows sending messages after
  authentication.
- **`crypto_utils.py`**: Helper library providing ECDH key generation,
  AES-GCM encryption, password hashing and other crypto utilities.

## Running

1. Install dependencies (requires Python 3 and the
   `cryptography` package):

   ```bash
   pip install cryptography
   ```

2. Start the server:

   ```bash
   python netsec3.v3/chat_server.py <port>
   ```

3. Start the client in a separate terminal:

   ```bash
   python netsec3.v3/chat_client.py <server_ip> <port>
   ```

Follow the interactive prompts to create an account, sign in and
exchange messages securely.
