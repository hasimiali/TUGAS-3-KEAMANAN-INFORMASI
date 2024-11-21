import random
from math import gcd
from typing import Tuple


def generate_prime_candidate(length: int) -> int:
    """Generate an odd integer randomly."""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1  # Ensure p is odd and has the correct bit length
    return p


def is_prime(n: int, k: int = 5) -> bool:
    """Test if a number is prime using Miller-Rabin."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as d*2^r + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test k times
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)  # Compute a^d % n
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime_number(length: int = 1024) -> int:
    """Generate a prime number."""
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def generate_keypair(keysize: int = 1024) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Generate RSA public and private keys."""
    p = generate_prime_number(keysize // 2)
    q = generate_prime_number(keysize // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Common choice for public exponent
    while gcd(e, phi) != 1:
        e = random.randint(2, phi)

    d = pow(e, -1, phi)
    return (e, n), (d, n)  # Public key, Private key


def encrypt_rsa(public_key: Tuple[int, int], plaintext: int) -> int:
    """Encrypt plaintext using public key."""
    e, n = public_key
    return pow(plaintext, e, n)


def decrypt_rsa(private_key: Tuple[int, int], ciphertext: int) -> int:
    """Decrypt ciphertext using private key."""
    d, n = private_key
    return pow(ciphertext, d, n)
