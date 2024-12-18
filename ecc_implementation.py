# Implementation of ECDSA (Elliptic Curve Digital Signature Algorithm) using ecdsa and cryptography libraries.

from ecdsa import SigningKey, NIST256p
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Example message to be signed
message = b"This is a test message for ECC signature."

# Generating a private-public key pair using NIST256p curve
private_key = SigningKey.generate(curve=NIST256p)
public_key = private_key.get_verifying_key()

# Signing the message
signature = private_key.sign(message)
print("Signed Message:", signature.hex())

# Verifying the signature
try:
    public_key.verify(signature, message)
    print("Signature is valid!")
except Exception as e:
    print("Signature verification failed:", str(e))

# Cryptography library demonstration
# Generate a private key using SECP256R1 curve
private_key_crypto = ec.generate_private_key(ec.SECP256R1(), default_backend())

# Deriving the public key from the private key
public_key_crypto = private_key_crypto.public_key()

# Signing the message
signature_crypto = private_key_crypto.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)
print("Cryptography Signed Message:", signature_crypto.hex())

# Verifying the signature
try:
    public_key_crypto.verify(
        signature_crypto,
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print("Cryptography Signature is valid!")
except Exception as e:
    print("Cryptography Signature verification failed:", str(e))
