"""Needham-Schroeder handshake helpers."""
from __future__ import annotations

import base64
import logging
import os
import threading
import time
from typing import Any

from . import crypto_utils

NONCE_SIZE = crypto_utils.AES_GCM_NONCE_SIZE


# State dictionaries are provided by the client module
handshake_events: dict[str, threading.Event]
session_keys: dict[str, dict]
client_username: str | None
channel_sk: bytes | None


def set_state(events: dict[str, threading.Event], keys: dict[str, dict], username: str | None, ch_sk: bytes | None) -> None:
    global handshake_events, session_keys, client_username, channel_sk
    handshake_events = events
    session_keys = keys
    client_username = username
    channel_sk = ch_sk


def generate_nonce_bytes() -> bytes:
    return os.urandom(NONCE_SIZE)


def request_session_key(sock: Any, server_address: tuple[str, int], peer: str) -> None:
    nonce1 = base64.b64encode(generate_nonce_bytes()).decode()
    handshake_events[peer] = threading.Event()
    session_keys[peer] = {"nonce1": nonce1, "state": "req"}
    sock.sendto(f"NS_REQ:{peer}:{nonce1}".encode(), server_address)


def send_relay_message(sock: Any, server_addr: tuple[str, int], header: str, peer: str, sender: str, *parts: str) -> None:
    blob = ":".join([header, peer, sender, *parts])
    sock.sendto(blob.encode(), server_addr)


def send_ns_ticket(sock: Any, server_address: tuple[str, int], peer: str) -> None:
    entry = session_keys.get(peer)
    if not entry:
        return
    key = entry["key"]
    nonce2 = generate_nonce_bytes()
    entry["nonce2"] = nonce2
    handshake_events.setdefault(peer, threading.Event()).clear()
    enc_nonce2 = crypto_utils.encrypt_aes_gcm_with_nonce(key, nonce2, nonce2)
    send_relay_message(
        sock,
        server_address,
        "NS_TICKET",
        peer,
        client_username or "",
        entry["ticket"],
        enc_nonce2,
    )
    entry["state"] = "ticket_sent"


def handle_ns_resp(sock: Any, server_address: tuple[str, int], peer: str, encrypted_blob: str) -> None:
    try:
        decrypted = crypto_utils.decrypt_aes_gcm(channel_sk, encrypted_blob)
        data = crypto_utils.deserialize_payload(decrypted)
    except Exception as exc:  # pragma: no cover - decryption failure
        logging.error("Failed to decrypt NS_RESP: %s", exc)
        return
    entry = session_keys.get(peer)
    if not entry or data.get("nonce1") != entry.get("nonce1"):
        logging.warning("Invalid or unexpected NS_RESP for %s", peer)
        return
    key_bytes = base64.b64decode(data.get("K_AB", ""))
    entry.update({
        "key": key_bytes,
        "ticket": data.get("ticket"),
        "timestamp": time.time(),
        "state": "got_key",
    })
    handshake_events.setdefault(peer, threading.Event()).clear()
    send_ns_ticket(sock, server_address, peer)


def handle_ns_ticket(sock: Any, server_address: tuple[str, int], sender: str, ticket: str, encrypted_nonce2: str) -> None:
    try:
        ticket_plain = crypto_utils.decrypt_aes_gcm(channel_sk, ticket)
        tdata = crypto_utils.deserialize_payload(ticket_plain)
        key_bytes = base64.b64decode(tdata.get("K_AB", ""))
        peer = tdata.get("sender", sender)
    except Exception as exc:  # pragma: no cover - malformed ticket
        logging.error("Failed to process ticket from %s: %s", sender, exc)
        return
    entry = session_keys.setdefault(peer, {})
    entry.update({"key": key_bytes, "ticket": ticket, "timestamp": time.time()})
    handshake_events.setdefault(peer, threading.Event()).clear()
    nonce2 = crypto_utils.decrypt_aes_gcm(key_bytes, encrypted_nonce2)
    nonce3 = generate_nonce_bytes()
    entry.update({"nonce2": nonce2, "nonce3": nonce3})
    n2_minus = (int.from_bytes(nonce2, "big") - 1) % (1 << (8 * NONCE_SIZE))
    plaintext = n2_minus.to_bytes(NONCE_SIZE, "big") + nonce3
    enc_auth = crypto_utils.encrypt_aes_gcm_with_nonce(key_bytes, nonce3, plaintext)
    send_relay_message(sock, server_address, "NS_AUTH", peer, client_username or "", enc_auth)
    entry["state"] = "auth_sent"


def complete_ns_auth(sock: Any, server_address: tuple[str, int], peer: str, encrypted_auth: str) -> None:
    entry = session_keys.get(peer)
    if not entry:
        return
    key = entry["key"]
    nonce2 = entry.get("nonce2")
    if not nonce2:
        return
    data = crypto_utils.decrypt_aes_gcm(key, encrypted_auth)
    n2_minus1 = data[:NONCE_SIZE]
    nonce3 = data[NONCE_SIZE:]
    expected = (int.from_bytes(nonce2, "big") - 1) % (1 << (8 * NONCE_SIZE))
    if n2_minus1 != expected.to_bytes(NONCE_SIZE, "big"):
        logging.warning("Nonce verification failed for peer %s", peer)
        return
    entry["nonce3"] = nonce3
    n3_minus = (int.from_bytes(nonce3, "big") - 1) % (1 << (8 * NONCE_SIZE))
    enc_fin = crypto_utils.encrypt_aes_gcm_with_nonce(key, nonce3, n3_minus.to_bytes(NONCE_SIZE, "big"))
    send_relay_message(sock, server_address, "NS_FIN", peer, client_username or "", enc_fin)
    entry["state"] = "complete"
    entry["timestamp"] = time.time()
    if peer in handshake_events:
        handshake_events[peer].set()


def handle_ns_fin(sender: str, encrypted_fin: str) -> None:
    entry = session_keys.get(sender)
    if not entry:
        return
    key = entry.get("key")
    nonce3 = entry.get("nonce3")
    if not (key and nonce3):
        return
    data = crypto_utils.decrypt_aes_gcm(key, encrypted_fin)
    expected = (int.from_bytes(nonce3, "big") - 1) % (1 << (8 * NONCE_SIZE))
    if data == expected.to_bytes(NONCE_SIZE, "big"):
        entry["state"] = "complete"
        entry["timestamp"] = time.time()
        handshake_events.setdefault(sender, threading.Event()).set()
