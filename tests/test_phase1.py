import unittest
import _bootstrap  # noqa: F401

from src.phase1 import (
    generate_prime,
    is_prime,
    extended_gcd,
    mod_inverse,
    generate_rsa_keys,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    simple_hash,
    CA,
    User
)

class TestPhase1(unittest.TestCase):
    def test_prime_generation(self):
        p = generate_prime(50, 200)
        self.assertTrue(50 <= p <= 200)
        self.assertTrue(is_prime(p))

    def test_extended_gcd(self):
        gcd, x, y = extended_gcd(30, 20)
        self.assertEqual(gcd, 10)
        self.assertEqual(30 * x + 20 * y, 10)

    def test_mod_inverse(self):
        inv = mod_inverse(3, 11)
        self.assertEqual((3 * inv) % 11, 1)

    def test_rsa_encryption_decryption(self):
        pub_key, priv_key = generate_rsa_keys()
        message = 42
        ciphertext = rsa_encrypt(message, pub_key)
        decrypted_message = rsa_decrypt(ciphertext, priv_key)
        self.assertEqual(message, decrypted_message)

    def test_rsa_signing_verification(self):
        pub_key, priv_key = generate_rsa_keys()
        message = 123
        signature = rsa_sign(message, priv_key)
        is_valid = rsa_verify(message, signature, pub_key)
        self.assertTrue(is_valid)

    def test_simple_hash(self):
        hash1 = simple_hash("A")
        self.assertTrue(0 <= hash1 <= 255)

        hash2 = simple_hash("AB")
        self.assertTrue(0 <= hash2 <= 255)

        # Consistent hashing
        self.assertEqual(simple_hash("Test"), simple_hash("Test"))

    def test_pki_flow(self):
        ca = CA()
        alice = User("Alice")

        # User receives certificate from CA
        alice.receive_certificate(ca)
        self.assertIsNotNone(alice.certificate)
        self.assertEqual(alice.certificate['user_id'], "Alice")

        # Verify Alice's certificate
        is_valid = alice.verify_certificate(alice.certificate, ca.public_key)
        self.assertTrue(is_valid)

        # Tamper with certificate and verify it fails
        tampered_cert = alice.certificate.copy()
        tampered_cert['n'] = tampered_cert['n'] + 1
        is_valid_tampered = alice.verify_certificate(tampered_cert, ca.public_key)
        self.assertFalse(is_valid_tampered)

if __name__ == '__main__':
    unittest.main()
