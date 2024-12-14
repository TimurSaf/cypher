import random

def gcd(a, b):
    """Computes the greatest common divisor (GCD) of two numbers.

    :param a: The first number.
    :type a: int
    :param b: The second number.
    :type b: int
    :return: The greatest common divisor.
    :rtype: int
    """
    if not isinstance(a, int):
        raise TypeError("a must take numeric values")

    if not isinstance(b, int):
        raise TypeError("b must take numeric values")

    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Computes the modular multiplicative inverse of a modulo m 
    using the extended Euclidean algorithm.

    :param a: The number for which to find the modular inverse.
    :type a: int
    :param m: The modulus, must be greater than 0.
    :type m: int
    :return: The modular inverse.
    :rtype: int
    :raises ValueError: If m is zero.
    """
    if m == 0:
        raise ValueError("Modulo cannot be zero")

    if not isinstance(m, int):
        raise TypeError("m must take numeric values")

    if not isinstance(a, int):
        raise TypeError("a must take numeric values")

    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0

    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0

    if x1 < 0:
        x1 += m0

    return x1

def generate_keys():
    """Generates a pair of keys (public and private) for RSA.

    :return: A tuple containing the public key and private key.
             The public key is represented as (e, n),
             and the private key as (d, n).
    """
    p = generate_large_prime(1024)  
    q = generate_large_prime(1024)
    
    while p == q:  
        q = generate_large_prime(1024)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  

    while gcd(e, phi) != 1:
        e = random.randint(2, phi)

    d = modinv(e, phi)
    
    return (e, n), (d, n)

def encrypt_message(public_key, message):
    """Encrypts a message using the public key.

    :param public_key: The public key, containing (e, n).
    :type public_key: tuple
    :param message: The message to encrypt.
    :type message: str
    :return: The encrypted message.
    :rtype: int
    :raises AttributeError: If the message is not a string.
    :raises ValueError: If the message is too long for the key size.
    """
    if not (isinstance(public_key[0], int) and isinstance(public_key[1], int)):
        raise ValueError("The key must consist of numbers")

    if not isinstance(message, str):
        raise AttributeError("Message must be a string")

    e, n = public_key
    message_int = int.from_bytes(message.encode(), 'big')

    if message_int >= n:
        raise ValueError("Message is too long for the key size")

    ciphertext = pow(message_int, e, n)
    
    return ciphertext

def decrypt_message(private_key, ciphertext):
    """Decrypts an encrypted message using the private key.

    :param private_key: The private key, containing (d, n).
    :type private_key: tuple
    :param ciphertext: The encrypted message.
    :type ciphertext: int
    :return: The decrypted message (str).
    :rtype: str
    :raises ValueError: If the ciphertext is not an integer or if decryption fails.
    """
    
    if not (isinstance(private_key[0], int) and isinstance(private_key[1], int)):
        raise ValueError("The key must consist of numbers")

    if not isinstance(ciphertext, int):
        raise ValueError("Ciphertext must be an integer")

    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)

    try:
        plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode()
    except Exception as e:
        raise ValueError("Decryption failed: " + str(e))

    return plaintext

def is_prime(n, k=128):
    """Checks if a number is prime using the Miller-Rabin primality test.

    :param n: The number to check.
    :type n: int
    :param k: The number of iterations for the test, default is 128.
              The larger the value of k, the higher the accuracy probability.
    :type k: int
    :return: True if n is prime; otherwise False.
    """
    if not isinstance(n, int):
        raise TypeError("n must take numeric values")
    
    if not isinstance(k, int):
        raise TypeError("k must take numeric values")
    
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

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

def generate_large_prime(bits):
    """Generates a large prime number of specified bit length.

    :param bits: The number of bits in the generated number.
    :type bits: int
    :return: The generated prime number.
    :rtype: int
    """
    if not isinstance(bits, int):
        raise TypeError("bits must take numeric values")

    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

