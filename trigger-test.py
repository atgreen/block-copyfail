#!/usr/bin/env python3
"""Trigger AF_ALG AEAD binds to test the blocker."""
import socket

tests = [
    ("aead", "authencesn(hmac(sha256),cbc(aes))"),
    ("aead", "gcm(aes)"),
    ("hash", "sha256"),
    ("skcipher", "cbc(aes)"),
]

for salg_type, salg_name in tests:
    sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        sock.bind((salg_type, salg_name))
        print(f"ALLOWED: {salg_type}/{salg_name}")
    except OSError as e:
        print(f"BLOCKED: {salg_type}/{salg_name} — {e}")
    finally:
        sock.close()
