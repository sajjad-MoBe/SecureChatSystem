import random
from .phase1 import rsa_sign, rsa_verify, simple_hash

# Diffie-Hellman Parameters
P = 65521
G = 11

def diffie_hellman_exchange(user_a, user_b, ca_public_key):
    """
    Simulates the authenticated Diffie-Hellman key exchange between User A and User B.
    Returns the Master Key (16-bit) if successful, otherwise raises an exception.
    """

    # 1. Verification of Certificates
    if not user_a.verify_certificate(user_b.certificate, ca_public_key):
        raise ValueError("User A failed to verify User B's certificate")
    if not user_b.verify_certificate(user_a.certificate, ca_public_key):
        raise ValueError("User B failed to verify User A's certificate")

    a_cert_public_key = (user_a.certificate['e'], user_a.certificate['n'])
    b_cert_public_key = (user_b.certificate['e'], user_b.certificate['n'])

    # 2. Key Exchange Setup
    # User A generates random private value and computes public value
    a_private = random.randint(1, P - 1)
    a_public = pow(G, a_private, P)

    # User A signs the hash of their public value
    a_hash = simple_hash(str(a_public).encode('utf-8'))
    a_signature = rsa_sign(a_hash, user_a.private_key)

    # User B generates random private value and computes public value
    b_private = random.randint(1, P - 1)
    b_public = pow(G, b_private, P)

    # User B signs the hash of their public value
    b_hash = simple_hash(str(b_public).encode('utf-8'))
    b_signature = rsa_sign(b_hash, user_b.private_key)

    # 3. Exchange and Authenticate
    # User B receives A's public value and signature, verifies it
    received_a_hash = simple_hash(str(a_public).encode('utf-8'))
    if not rsa_verify(received_a_hash, a_signature, a_cert_public_key):
        raise ValueError("User B failed to verify User A's DH signature")

    # User A receives B's public value and signature, verifies it
    received_b_hash = simple_hash(str(b_public).encode('utf-8'))
    if not rsa_verify(received_b_hash, b_signature, b_cert_public_key):
        raise ValueError("User A failed to verify User B's DH signature")

    # 4. Generate Shared Secret
    k_a = pow(b_public, a_private, P)
    k_b = pow(a_public, b_private, P)

    assert k_a == k_b, "DH shared secrets do not match"

    # 5. Extract 16-bit Master Key
    master_key = k_a % (2**16)

    return master_key
