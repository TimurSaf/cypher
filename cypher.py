import argparse
import sys
import socket
import RSA
import DES
import random
import cesar
import viginer
from ipaddress import ip_address


def create_parser():
    """
    Создает парсер для обработки аргументов командной строки.

    :return: Объект класса ArgumentParser c присвоенными атрибутами.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument('-k', '--key')
    parser.add_argument("-i", "--ip_addr")
    parser.add_argument("-d", "--decrypt", action="store_true", default=False)
    parser.add_argument("-g", "--gen_key", action="store_true", default=False)

    return parser


def factorization(n):
    """
    Факторизует число n, показывает, на какие множители оно раскладывается.

    :param n: Число, которое надо факторизовать.
    :type n: int.
    :raise TypeError: Возникает, если n не является целым.
    :return: список всех простых делителей числа.
    :rtype: list.
    """
    if not isinstance(n, int):
        raise TypeError
    i = 2
    primes = set()
    while i <= n ** 0.5:
        while n % i == 0:
            primes.add(i)
            n = n/i
        i += 1
    if n > 1:
        primes.add(int(n))
    return list(primes)


def create_primitive_root(p):
    """
    Создает первообразный корень g для числа p.

    :param p: Простое число, от которого берем первообразный корень.
    :type p: int.
    :raise TypeError: Возникает, когда p не является целым.
    :raise ValueError: Если число p - составное, выдает ошибку ValueError.
    :return: Возвращаем первообразный корень g.
    :rtype: int.
    """
    if not isinstance(p, int):
        raise TypeError
    if not RSA.is_prime(p):
        raise ValueError

    func_euler = p - 1
    i = 2
    g = 2
    while i < p:
        condition_1 = RSA.gcd(i, p) == 1
        condition_2 = pow(i, func_euler//2, p) != 0
        condition_3 = True
        primes_euler = factorization(func_euler)
        j = 0
        while all([condition_3, condition_2, condition_1, j < len(primes_euler)]):
            li = func_euler//primes_euler[j]
            if pow(i, li, int(p)) == 1:
                condition_3 = False
            j += 1
        if all([condition_1, condition_2, condition_3]):
            g = i
            break
        i += 1
    return g


def main():
    """
    Главная функция, отвечающая за интерфейс командной строки

    :raise ValueError: Происходит, когда не указан ip адрес, или не указан ключ (или указан, но не верно)
    """
    parser_args = create_parser()
    namespace = parser_args.parse_args(sys.argv[1:])
    if namespace.command == "send":
        if not namespace.ip_addr:
            raise ValueError
        ip = ip_address(namespace.ip_addr)
        port = 65341
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((namespace.ip_addr, port))
            p = RSA.generate_large_prime(1024)
            g = create_primitive_root(p)
            a = random.randint(0, 10**100) | 10**100
            A = pow(g, a, p)
            keys = f"{p}\n{g}\n{A}"
            s.sendall(keys.encode("utf-8"))
            B = int((s.recv(1024)).decode("utf-8"))
            diffie_hellman_number = str(pow(B, a, p))
            diffie_hellman_number += "0"*(14 - len(diffie_hellman_number))
            key_des = diffie_hellman_number[:14]
            key_des = bytes([int(key_des[i:i+2]) for i in range(0, 14, 2)])
            f = open(namespace.file, "rb")
            f_1024 = f.read(1024)
            while len(f_1024) == 1024:
                blok_1024 = b""
                for i in range(128):
                    ci = f_1024[i*8:i*8 + 8]
                    ci = DES.des(ci, key_des)
                    blok_1024 += bytes([int(ci[j:j+8], 2) for j in range(0, 64, 8)])
                s.sendall(blok_1024)
                f_1024 = f.read(1024)
            f_len_8 = len(f_1024) // 8
            blok_last = b""
            for i in range(f_len_8):
                ci = f_1024[i*8:i*8 + 8]
                ci = DES.des(ci, key_des)
                blok_last += bytes([int(ci[j:j+8], 2) for j in range(0, 64, 8)])
            last_byte = DES.des(DES.pkcs5(f_1024[f_len_8 * 8:]), key_des)
            blok_last += bytes([int(last_byte[j:j+8], 2) for j in range(0, 64, 8)])
            s.sendall(blok_last)
    elif namespace.command == "get":
        if not namespace.ip_addr:
            raise ValueError
        ip = ip_address(namespace.ip_addr)
        port = 65341
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((namespace.ip_addr, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                keys = (conn.recv(1024)).decode("utf-8")
                p, g, A = keys.split("\n")
                b = random.randint(0, 10**100) | 10**100
                B = pow(int(g), b, int(p))
                conn.sendall((str(B)).encode("utf-8"))
                diffie_hellman_number = str(pow(int(A), b, int(p)))
                diffie_hellman_number += "0" * (14 - len(diffie_hellman_number))
                key_des = diffie_hellman_number[:14]
                key_des = bytes([int(key_des[i:i + 2]) for i in range(0, 14, 2)])
                f = open(namespace.file, "wb")
                enc_data = conn.recv(1024)
                while len(enc_data) == 1024:
                    blok_1024 = b""
                    for i in range(128):
                        ci = enc_data[i*8:i * 8 + 8]
                        ci = DES.des(ci, key_des, "decrypt")
                        blok_1024 += bytes(int(ci[j:j+8], 2) for j in range(0, 64, 8))
                    f.write(blok_1024)
                    enc_data = conn.recv(1024)
                enc_data_len_8 = len(enc_data) // 8 - 1
                blok_last = b""
                for i in range(enc_data_len_8):
                    ci = enc_data[i*8:i*8 + 8]
                    ci = DES.des(ci, key_des, "decrypt")
                    blok_last += bytes(int(ci[j:j+8], 2) for j in range(0, 64, 8))
                last_byte = DES.des(enc_data[enc_data_len_8 * 8:], key_des, "decrypt")
                last_byte = bytes([int(last_byte[i:i+8], 2) for i in range(0, 64, 8)])
                blok_last += last_byte[:last_byte[-1]]
                f.write(blok_last)
    elif namespace.command == "caesar":
        if not namespace.key:
            raise ValueError
        if not namespace.key.isdigit():
            raise ValueError
        f = open(namespace.file, "r")
        if namespace.decrypt:
            decrypted_f = open("decrypted_" + namespace.file, "w")
            for line in f:
                dec_line = cesar.caesar_decrypt(line, int(namespace.key))
                decrypted_f.write(dec_line)
            decrypted_f.close()
        else:
            encrypted_f = open("encrypted_" + namespace.file, "w")
            for line in f:
                enc_line = cesar.caesar_encrypt(line, int(namespace.key))
                encrypted_f.write(enc_line)
            encrypted_f.close()
        f.close()
    elif namespace.command == "vignere":
        if not namespace.key:
            raise ValueError
        if not namespace.key.isalpha():
            raise ValueError
        f = open(namespace.file, "r")
        if namespace.decrypt:
            decrypted_f = open("decrypted_" + namespace.file, "w")
            decrypted_f.write(viginer.viginer_decrypt(f.read(), namespace.key))
        else:
            encrypted_f = open("encrypted_" + namespace.file, "w")
            encrypted_f.write(viginer.viginer_encrypt(f.read(), namespace.key))
        f.close()
    elif namespace.command == "RSA":
        if namespace.gen_key:
            f = open(namespace.file, "w")
            keys = RSA.generate_keys()
            strings_keys = f"{keys[0][0]} {keys[0][1]}\n{keys[1][0]} {keys[1][1]}"
            f.write(strings_keys)
            f.close()
        elif namespace.decrypt:
            if not namespace.key:
                raise ValueError
            f = open(namespace.file, "r")
            f_keys = open(namespace.key, "r")
            keys_private = tuple((int(key) for key in (f_keys.readlines()[1]).split(" ")))
            decrypted_f = open("decrypt_" + namespace.file, "w")
            decrypted_text = RSA.decrypt_message(keys_private, int(f.read()))
            decrypted_f.write(decrypted_text)
            f.close()
            f_keys.close()
        else:
            if not namespace.key:
                raise ValueError
            f = open(namespace.file, "r")
            f_keys = open(namespace.key, "r")
            keys_public = tuple((int(key) for key in (f_keys.readlines()[0]).split(" ")))
            encrypted_f = open("encrypt_" + namespace.file, "w")
            encrypted_text = RSA.encrypt_message(keys_public, f.read())
            encrypted_f.write(str(encrypted_text))
            f.close()
            f_keys.close()


if __name__ == "__main__":
    main()
