import pytest
from cesar import caesar_encrypt, caesar_decrypt


def test_caesar_encrypt_valid():
    assert caesar_encrypt("abc", 1) == "bcd"


def test_caesar_encrypt_over26():
    assert caesar_encrypt("XYZ", 3) == "ABC"


def test_caesar_encrypt_aiplove():
    assert caesar_encrypt("I love AIP 99!", 5) == "N qtaj FNU 99!"


def test_caesar_decrypt_valid():
    assert caesar_decrypt("bcd", 1) == "abc"


def test_caesar_decrypt_over26():
    assert caesar_decrypt("ABC", 3) == "XYZ"


def test_caesar_decrypt_aiplove():
    assert caesar_decrypt("N qtaj FNU 99!", 5) == "I love AIP 99!"


def test_caesar_encrypt_invalid_text_type():
    with pytest.raises(TypeError):
        caesar_encrypt(123, 3)


def test_caesar_encrypt_invalid_shift_type():
    with pytest.raises(TypeError):
        caesar_encrypt("abc", "1")


def test_caesar_decrypt_invalid_text_type():
    with pytest.raises(TypeError):
        caesar_decrypt(123, 3)


def test_caesar_decrypt_invalid_shift_type():
    with pytest.raises(TypeError):
        caesar_decrypt("abc", "1")
