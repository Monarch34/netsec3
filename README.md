# Secure Chat

This project implements an encrypted UDP chat server and client using Python.

## Running

1. **Install dependencies**
   ```bash
   python -m pip install -r requirements.txt
   ```

2. **Start the server**
   ```bash
   python -m netsec3.v3.chat_server 15000
   ```

3. **Run the secure client**
   ```bash
   python -m netsec3.v3.chat_client_secure 127.0.0.1 15000
   ```

## Tests

The test suite uses `pytest` and also runs `flake8` for linting.

```bash
pytest -q
```

## Authentication protocol

Clients first establish a channel key via an ECDH exchange. Signup stores a PBKDF2 password verifier. Signin is performed using a challenge–response HMAC over a server nonce. After authentication users can exchange Needham–Schroeder tickets to derive per‑peer session keys.

