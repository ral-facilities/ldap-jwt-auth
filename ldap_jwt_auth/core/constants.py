"""
Module for the constants of the application.
"""
import sys

from ldap_jwt_auth.core.config import config

# Read the contents of the private and public key files into constants. These are used for encoding and decoding of JWT
# access and refresh tokens.
try:
    with open(config.authentication.private_key_path, "r") as f:
        PRIVATE_KEY = f.read()
except FileNotFoundError as exc:
    sys.exit(f"Cannot find private key: {exc}")

try:
    with open(config.authentication.public_key_path, "r") as f:
        PUBLIC_KEY = f.read()
except FileNotFoundError as exc:
    sys.exit(f"Cannot find public key: {exc}")
