import DES
import cypher
import pytest
import sys


def test_key_gen_valid_key1():
    key = b"1234567"
    correct_key = ['001011000100101001100101101001010100110100101101',
                   '011111011001010101010000001001110101111001000000',
                   '010001101100000011001111110110001010000101110010',
                   '001110111100000100010110101001011100111000001100',
                   '001011000000100110101011010110000011011011010010',
                   '101100110010000000111101101111011100000000101101',
                   '100011010000111010010000000000100111111011000010',
                   '010101100011101010111100101111001010000100110101',
                   '001000001100110110100101101001110100000000111101',
                   '110100010010100100010111010000110011101111000010',
                   '001001011010011010110001101101001000000100111101',
                   '110101110001010010100110010000110001111011000110',
                   '111110101000001011010000010111001010000110111001',
                   '000111001101001000101110001000110101110001001101',
                   '101000100001000101011110010010101011000110110010',
                   '010100100111011010010011100111001110000100111011']
    assert (DES.key_gen(key) == correct_key)


def test_key_gen_valid_key2():
    key = b"python3"
    correct_key = ['010010101001100111100010101001110101011101111100',
                   '110100111010001000110001110011110101111001000010',
                   '100011011001111010010110010111001110001101111100',
                   '011101100011001011001110101100011101110011001100',
                   '001110101101010001100000110010001011011010110011',
                   '110010000100100101111110101111110110111000101101',
                   '101001001110001100011101001110100101101111010010',
                   '000001110001111100100011100101011110000100110111',
                   '011110101000001101001001101001010100101111011101',
                   '000010011101000000111111010100111011001011010011',
                   '101001010000100111011110111101111000010100101101',
                   '001101100110101010100001000010100011111111001110',
                   '100110110011110100110000011111001111000110110101',
                   '110011000010011011011101011000110100110011101011',
                   '010101111101011000001100110011101011100100011011',
                   '111101000000110110101001101111011000010100111011']
    assert (DES.key_gen(key) == correct_key)


def test_key_gen_invalid_type():
    with pytest.raises(TypeError):
        DES.key_gen(1234567)


def test_key_gen_invalid_len():
    with pytest.raises(ValueError):
        DES.key_gen(bytes(10))


def test_pkcs5_valid_1():
    str_bytes = bytes(7)
    assert DES.pkcs5(str_bytes) == (bytes(7) + bytes([1]))


def test_pkcs5_valid_2():
    str_bytes = b"fstr"
    assert DES.pkcs5(str_bytes) == b'fstr\x04\x04\x04\x04'


def test_pkcs5_invalid_type():
    with pytest.raises(TypeError):
        DES.pkcs5("dddfe")


def test_feistel_valid_1():
    right_res = "00010101000100011000100001011001"
    assert DES.feistel("01001010101010100010101101010100",
                       "100010111010000101101010110101010100101010101011") == right_res


def test_feistel_valid_2():
    right_res = '00011101100000001110110101001010'
    assert DES.feistel("01000101011010100010101001011010",
                       "100010111010000101101010110101010100101010101011") == right_res


def test_feistel_invalid_type():
    with pytest.raises(TypeError):
        DES.feistel(112313, 222333)


def test_feistel_invalid_len():
    with pytest.raises(ValueError):
        DES.feistel("010010101010101000101011010101001111",
                    "1000101110100001011010101101010101001010101010111")


def test_des_valid_enc():
    message = b"distantt"
    key = b"1234567"
    assert DES.des(message, key) == '1001011010110101001111000001011110100001110100100100100000111101'


def test_des_valid_decrypt():
    message = b"f2d4e12h"
    key = b"nc342n3"
    assert DES.des(message, key) == '0101001100000001001010110100010110110111001101111011100010110000'


def test_des_invalid_len():
    with pytest.raises(ValueError):
        DES.des(b"not_right_len", b"12345678")


def test_des_invalid_type():
    with pytest.raises(TypeError):
        DES.des("encrypt_", "1233412")


def test_factorization_valid_simple():
    right_ans = [3, 5]
    assert cypher.factorization(15) == right_ans


def test_factorization_valid_hard():
    right_ans = [2, 3, 269]
    assert cypher.factorization(14526) == [2, 3, 269]


def test_factorization_invalid_type():
    with pytest.raises(TypeError):
        cypher.factorization("1231")


def test_create_primitive_root_simple():
    right_ans = 3
    assert cypher.create_primitive_root(17) == 3


def test_create_primitive_root_hard():
    right_ans = 3
    p = 80189158048884962228709424475085883512009868257279949933825083185637751912759
    assert cypher.create_primitive_root(p) == 3


def test_create_primitive_root_invalid_type():
    with pytest.raises(TypeError):
        cypher.create_primitive_root("18897")


def test_create_primitive_root_invalid_not_prime():
    with pytest.raises(ValueError):
        cypher.create_primitive_root(10)
