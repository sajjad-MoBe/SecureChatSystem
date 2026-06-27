import unittest
import _bootstrap  # noqa: F401

from src.phase1 import CA, User, generate_rsa_keys
from src.phase2 import diffie_hellman_exchange

class TestPhase2(unittest.TestCase):
    def test_authenticated_dh(self):
        ca = CA()
        alice = User("Alice")
        bob = User("Bob")

        alice.receive_certificate(ca)
        bob.receive_certificate(ca)

        master_key = diffie_hellman_exchange(alice, bob, ca.public_key)

        self.assertIsNotNone(master_key)
        self.assertTrue(0 <= master_key < 65536) # 16-bit

    def test_dh_fails_invalid_certificate(self):
        ca = CA()
        alice = User("Alice")
        bob = User("Bob")

        alice.receive_certificate(ca)
        bob.receive_certificate(ca)

        # Tamper with Bob's cert
        bob.certificate['n'] += 1

        with self.assertRaises(ValueError):
            diffie_hellman_exchange(alice, bob, ca.public_key)

    def test_dh_uses_certificate_public_key_for_signature_verification(self):
        ca = CA()
        alice = User("Alice")
        bob = User("Bob")

        alice.receive_certificate(ca)
        bob.receive_certificate(ca)

        # If the exchange incorrectly trusts the mutable User key fields
        # instead of the CA-signed certificate key, this tampering would pass.
        alice.public_key, alice.private_key = generate_rsa_keys()

        with self.assertRaises(ValueError):
            diffie_hellman_exchange(alice, bob, ca.public_key)

if __name__ == '__main__':
    unittest.main()
