import random

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(min_val=50, max_val=200):
    """Generates a prime number between min_val and max_val."""
    primes = [i for i in range(min_val, max_val + 1) if is_prime(i)]
    if not primes:
        raise ValueError(f"No primes found in range {min_val} to {max_val}")
    return random.choice(primes)

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    """Calculates the modular inverse."""
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % phi

def generate_rsa_keys():
    """Generates RSA public and private keys."""
    p = generate_prime(50, 200)
    q = generate_prime(50, 200)
    while p == q:
        q = generate_prime(50, 200)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 257
    # Ensure gcd(e, phi) == 1
    while extended_gcd(e, phi)[0] != 1:
        # If 257 doesn't work, we pick the next suitable odd number
        e += 2

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_encrypt(message, public_key):
    """Encrypts a message using RSA public key."""
    e, n = public_key
    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    """Decrypts a ciphertext using RSA private key."""
    d, n = private_key
    return pow(ciphertext, d, n)

def rsa_sign(message, private_key):
    """Signs a message using RSA private key."""
    d, n = private_key
    return pow(message, d, n)

def rsa_verify(message, signature, public_key):
    """Verifies an RSA signature."""
    e, n = public_key
    decrypted_signature = pow(signature, e, n)
    return message == decrypted_signature

def simple_hash(data_bytes):
    """
    Simple hash function: Takes input bytes, splits into 16-bit blocks (2 bytes),
    and XORs them. Output is an 8-bit value (0 to 255).
    """
    if isinstance(data_bytes, str):
        data_bytes = data_bytes.encode('utf-8')

    if not data_bytes:
        return 0

    # Ensure length is even for 16-bit blocks, padding with 0 if necessary
    if len(data_bytes) % 2 != 0:
        data_bytes = data_bytes + b'\x00'

    result = 0
    for i in range(0, len(data_bytes), 2):
        block = (data_bytes[i] << 8) | data_bytes[i+1]
        result ^= block

    # XOR the high and low 8 bits of the final 16-bit result to get an 8-bit output
    high_byte = (result >> 8) & 0xFF
    low_byte = result & 0xFF
    return high_byte ^ low_byte

class CA:
    def __init__(self):
        self.public_key, self.private_key = generate_rsa_keys()

    def issue_certificate(self, user_id, user_pub_key):
        """
        Issues a digital certificate for a user.
        user_pub_key is (e, n).
        """
        e, n = user_pub_key
        # Construct the string to hash: user_id || n || e
        data_to_hash = f"{user_id}{n}{e}".encode('utf-8')
        hashed_data = simple_hash(data_to_hash)

        signature = rsa_sign(hashed_data, self.private_key)

        certificate = {
            'user_id': user_id,
            'n': n,
            'e': e,
            'ca_signature': signature
        }
        return certificate

class User:
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = generate_rsa_keys()
        self.certificate = None

    def receive_certificate(self, ca):
        self.certificate = ca.issue_certificate(self.name, self.public_key)

    def verify_certificate(self, certificate, ca_public_key):
        """Verifies a given certificate using the CA's public key."""
        user_id = certificate['user_id']
        n = certificate['n']
        e = certificate['e']
        signature = certificate['ca_signature']

        data_to_hash = f"{user_id}{n}{e}".encode('utf-8')
        hashed_data = simple_hash(data_to_hash)

        return rsa_verify(hashed_data, signature, ca_public_key)
