"""Helper utilities for the chat server."""

from __future__ import annotations

import base64
import logging
import os
import time
import re
from collections import defaultdict
from typing import Tuple, Any, Dict

try:
    from . import crypto_utils
    from . import config
except ImportError:  # pragma: no cover - fallback when run as script
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    import crypto_utils  # type: ignore
    import config  # type: ignore

# Precompiled username pattern
USERNAME_RE = re.compile(config.USERNAME_PATTERN)

# Track requests per IP for simple rate limiting
request_tracker: dict[str, list[float]] = defaultdict(list)

# Cache of used internal nonces
used_internal_nonces: dict[str, float] = {}

# Cache of recently seen message nonces to prevent replay
used_message_nonces: dict[str, float] = {}


def reset_caches() -> None:
    """Reset rate limiting and nonce caches.

    This is primarily used in tests where multiple server instances are
    started sequentially in the same process.
    """
    request_tracker.clear()
    used_internal_nonces.clear()
    used_message_nonces.clear()


def validate_username_format(username: str) -> bool:
    """Return True if the username matches the allowed format."""
    return isinstance(username, str) and bool(USERNAME_RE.fullmatch(username))


def validate_password_format(password: str) -> bool:
    """Return True if the password meets length requirements."""
    return isinstance(password, str) and 6 <= len(password) <= 128


def validate_message_content(content: str) -> bool:
    """Return True if message content length is within allowed bounds."""
    return isinstance(content, str) and 1 <= len(content) <= config.MAX_MSG_LENGTH


def validate_broadcast_content(content: str) -> bool:
    """Return True if broadcast content length is within allowed bounds."""
    return isinstance(content, str) and 1 <= len(content) <= config.MAX_MSG_LENGTH


def validate_username_password_format(username: str, password: str) -> Tuple[bool, str]:
    """Validate username and password and return (is_valid, message)."""
    if not validate_username_format(username):
        return False, "Invalid username format."
    if not validate_password_format(password):
        return False, "Password must be 6-128 characters."
    return True, ""


def is_rate_limited(ip_address: str) -> bool:
    """Return True if the IP address has exceeded the request rate limit."""
    now = time.time()
    timestamps = request_tracker[ip_address]
    timestamps.append(now)
    # Remove entries outside the window
    request_tracker[ip_address] = [t for t in timestamps if now - t < config.REQUEST_WINDOW_SECONDS]
    return len(request_tracker[ip_address]) > config.MAX_REQUESTS_PER_WINDOW


def validate_internal_nonce(nonce_value: str) -> bool:
    """Return True if the internal nonce is unused and not expired."""
    now = time.time()
    ts = used_internal_nonces.get(nonce_value)
    if ts and now - ts < config.INTERNAL_NONCE_EXPIRY_SECONDS:
        return False
    used_internal_nonces[nonce_value] = now
    for n, t in list(used_internal_nonces.items()):
        if now - t > config.INTERNAL_NONCE_EXPIRY_SECONDS:
            del used_internal_nonces[n]
    return True


def validate_message_nonce(nonce_value: str) -> bool:
    """Return True if the message nonce is unused within the timestamp window."""
    now = time.time()
    ts = used_message_nonces.get(nonce_value)
    if ts and now - ts < config.TIMESTAMP_WINDOW_SECONDS:
        return False
    used_message_nonces[nonce_value] = now
    # Prune old nonces to avoid unbounded growth
    for n, t in list(used_message_nonces.items()):
        if now - t > config.TIMESTAMP_WINDOW_SECONDS:
            del used_message_nonces[n]
    return True


def validate_timestamp_internal(timestamp_str: str) -> bool:
    """Return True if a timestamp string is within the allowed window."""
    try:
        ts = float(timestamp_str)
    except ValueError:
        return False
    return abs(time.time() - ts) <= config.TIMESTAMP_WINDOW_SECONDS


def send_encrypted_response(
    sock: Any,
    client_address: Tuple[str, int],
    channel_sk: bytes,
    response_payload_dict: Dict[str, Any],
) -> None:
    """Utility to encrypt and send a JSON payload back to the client."""
    resp_bytes = crypto_utils.serialize_payload(response_payload_dict)
    enc_blob = crypto_utils.encrypt_aes_gcm(channel_sk, resp_bytes)
    sock.sendto(enc_blob.encode("utf-8"), client_address)
    logging.debug("RESP to %s: %s", client_address, enc_blob)


def relay_raw(
    sock: Any,
    header: str,
    sender_addr: Tuple[str, int],
    enc_blob: str,
    client_sessions: Dict[Tuple[str, int], Dict[str, Any]],
    active_usernames: Dict[str, Tuple[str, int]],
) -> None:
    """Decrypt relay payload from sender and re-encrypt for recipient."""
    sender_sess = client_sessions.get(sender_addr)
    if not sender_sess or not sender_sess.get("channel_sk"):
        logging.warning("Cannot relay %s from unknown sender %s", header, sender_addr)
        return
    try:
        plain_bytes = crypto_utils.decrypt_aes_gcm(sender_sess["channel_sk"], enc_blob)
        plain = plain_bytes.decode()
    except Exception as exc:
        logging.warning("Failed to decrypt %s from %s: %s", header, sender_addr, exc)
        return

    target, _, rest = plain.partition(":")
    if not rest:
        logging.warning("Malformed %s from %s", header, sender_addr)
        return
    target_addr = active_usernames.get(target)
    target_sess = client_sessions.get(target_addr) if target_addr else None
    if not (target_addr and target_sess and target_sess.get("channel_sk")):
        logging.info("%s target %s not found", header, target)
        return
    try:
        enc_for_target = crypto_utils.encrypt_aes_gcm(target_sess["channel_sk"], plain_bytes)
        sock.sendto(f"{header}:{enc_for_target}".encode("utf-8"), target_addr)
        logging.debug("Forwarded %s to %s", header, target)
        sender_user = sender_sess.get("username", sender_addr)
        logging.info(
            "Relayed %s from %s to %s (len=%d)", header, sender_user, target, len(enc_blob)
        )
    except Exception as exc:
        logging.error("Error relaying %s from %s to %s: %s", header, sender_addr, target_addr, exc)


# ---------------------------------------------------------------------------
# Session tracking / notifications
# ---------------------------------------------------------------------------

# Client session tracking is managed by ``ChatServer``

def notify_user_logout(
    sock: Any,
    username: str,
    client_sessions: Dict[Tuple[str, int], Dict[str, Any]],
) -> None:
    """Notify all connected clients that ``username`` signed out."""
    for addr, sess in list(client_sessions.items()):
        if (
            sess.get("username")
            and sess.get("username") != username
            and sess.get("channel_sk")
        ):
            send_encrypted_response(
                sock,
                addr,
                sess["channel_sk"],
                {"type": "USER_LOGOUT", "user": username},
            )

