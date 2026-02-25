#!/usr/bin/env python3
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

h = hashlib.sha256(b"test data")
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
