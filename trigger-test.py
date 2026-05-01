#!/usr/bin/env python3
"""Trigger an authencesn AF_ALG bind to test the blocker."""
import socket, struct

sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
try:
    sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    print("FAIL: bind succeeded (blocker not working)")
except OSError as e:
    print(f"BLOCKED: {e}")
finally:
    sock.close()
