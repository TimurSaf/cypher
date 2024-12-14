import pytest
from RSA import (
    generate_keys,
    encrypt_message,
    decrypt_message,
    modinv,
    gcd,
    is_prime,
    generate_large_prime
)

def test_modinv1():
    assert modinv(3, 11) == 4

def test_modinv2():
    assert modinv(10, 17) == 12

def test_modinv3():
    with pytest.raises(ValueError):
        modinv(3, 0)

def test_generate_keys():
    public_key, private_key = generate_keys()
    assert isinstance(public_key, tuple)
    assert isinstance(private_key, tuple)

def test_generate_keys_len():
    public_key, private_key = generate_keys()
    assert len(public_key) == 2
    assert len(private_key) == 2

def test_generate_keys_public():
    public_key, _ = generate_keys()
    assert public_key[0] > 1
    assert public_key[1] > 1

def test_generate_keys_private():
    _, private_key = generate_keys()
    assert private_key[0] > 1
    assert private_key[1] > 1

def test_encrypt_message():
    public_key, _ = generate_keys()
    message = "Test Message"
    ciphertext = encrypt_message(public_key, message)
    assert isinstance(ciphertext, int)

def test_encrypt_message_public():
    public_key, _ = generate_keys()
    with pytest.raises(AttributeError):
        encrypt_message(public_key, 12345)

def test_encrypt_message_large():
    public_key, _ = generate_keys()
    large_message = "a" * 2048
    with pytest.raises(ValueError):
        encrypt_message(public_key, large_message)

def test_decrypt_message():
    public_key, private_key = generate_keys()
    message = "Test Message"
    ciphertext = encrypt_message(public_key, message)
    decrypted_message = decrypt_message(private_key, ciphertext)
    assert decrypted_message == message

def test_decrypt_message_int():
    _, private_key = generate_keys()
    with pytest.raises(ValueError):
        decrypt_message(private_key, "not an int")

def test_decrypt_message_value():
    _, private_key = generate_keys()
    with pytest.raises(ValueError):
        decrypt_message(private_key, -1)

def test_encrypt_decrypt_cycle():
    message = "Hello, RSA!"
    public_key, private_key = generate_keys()
    ciphertext = encrypt_message(public_key, message)
    decrypted_message = decrypt_message(private_key, ciphertext)
    assert decrypted_message == message, "The decrypted message must match the original one"

def test_invalid_message_encrypt():
    public_key, _ = generate_keys()
    with pytest.raises(AttributeError):
        encrypt_message(public_key, 123)

def test_invalid_cipher_decrypt():
    _, private_key = generate_keys()
    with pytest.raises(ValueError):
        decrypt_message(private_key, "Invalid Cipher")

def test_prime_generation_isprime():
    prime = generate_large_prime(1024)
    assert is_prime(prime), "The generated number must be simple"

def test_large_primes():
    """Тесты для больших простых чисел"""
    assert is_prime(7919)  # Простое число
    assert is_prime(104729)  # Простое число

def test_large_composites():
    """Тесты для больших составных чисел"""
    assert not is_prime(1000000)  # Составное число
    assert not is_prime(1000003 * 100003)  # Произведение двух простых

def test_type_errors():
    """Тесты для ошибок типов"""
    with pytest.raises(TypeError):
        is_prime("a string")

    with pytest.raises(TypeError):
        is_prime(5.5)

def test_prime_generation_1024():
    prime = generate_large_prime(1024)
    assert prime.bit_length() == 1024, "The generated number must have 1024 bits"

def test_gcd_valid1():
    assert gcd(54, 24) == 6, "The largest common divisor for 54 and 24 should be 6"

def test_gcd2():
    assert gcd(0, 5) == 5

def test_gcd_valid_prime():
    assert gcd(17, 13) == 1, "The largest common divisor for 17 and 13 should be 1"

def test_modinv_valid2():
    assert modinv(3, 26) == 9, "The inverse element for 3 modulo 26 should be 9"

def test_modinv_error():
    with pytest.raises(ValueError):
        modinv(2, 0)

def test_encrypt_decrypt_large_message():
    message = "A" * 100
    public_key, private_key = generate_keys()
    ciphertext = encrypt_message(public_key, message)
    decrypted_message = decrypt_message(private_key, ciphertext)
    assert decrypted_message == message, "The decrypted long message must match the original one"

def test_altered_ciphertext():
    message = "Test message"
    public_key, private_key = generate_keys()
    ciphertext = encrypt_message(public_key, message)
    altered_ciphertext = ciphertext ^ 1
    with pytest.raises(ValueError):
        decrypt_message(private_key, altered_ciphertext)
