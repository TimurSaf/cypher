import pytest
from viginer import viginer_encrypt, viginer_decrypt


def test_valid_encryption():
    encrypted = viginer_encrypt("HELLO", "KEY")
    assert encrypted == "RIJVS"


def test_valid_decryption():
    decrypted = viginer_decrypt("RIJVS", "KEY")
    assert decrypted == "HELLO"


def test_invalid_key_en():
    with pytest.raises(ValueError):
        viginer_encrypt("HELLO", "123")


def test_invalid_key_de():
    with pytest.raises(ValueError):
        viginer_decrypt("RIJVS", "123")


def test_invalid_plaintext():
    with pytest.raises(ValueError):
        viginer_encrypt("HELLO123", "KEY")


def test_invalid_ciphertext():
    with pytest.raises(ValueError):
        viginer_decrypt("RIJVS123", "KEY")
