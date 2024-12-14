def key_gen(key56: bytes):
    """
    Генерирует 16 ключей по 48 бит для алгоритма DES из 56-битного ключа.

    :param key56: 56-битный ключ в байтовом формате.
    :type key56: bytes.
    :raise TypeError: Возникает, когда key56 не байтовая строка.
    :raise ValueError: Возникает, когда key56 другой длины(не семь).
    :return: Список из 16 ключей по 48 бит в двоичном формате.
    :rtype: list.
    """
    if not isinstance(key56, bytes):
        raise TypeError
    if not (len(key56) == 7):
        raise ValueError

    key64 = ""
    key56 = key56.hex()
    bin_key56 = "".join((bin(int(key56[i:i+2], 16))[2:]).zfill(8) for i in range(0, len(key56), 2))
    ls = [bin_key56[i:i + 7] for i in range(0, 56, 7)]
    for num in ls:
        key64 += num + ("0" if num.count("1") % 2 == 1 else "1")
    ci = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
          10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
    di = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
          14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    sd = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    fin = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    key64 = "".join(key64[i-1] for i in ci+di)
    ci = key64[:28]
    di = key64[28:]
    lsk = [""] * 16
    for i in range(0, 16):
        ci = ci[sd[i]:] + ci[:sd[i]]
        di = di[sd[i]:] + di[:sd[i]]
        prom_key = ci + di
        for j in fin:
            lsk[i] += prom_key[j - 1]
    return lsk


def pkcs5(string_bytes: bytes):
    """
    Применяет схему дополнения PKCS#5 к строке байтов.

    :param string_bytes: Строка байтов, которая будет дополнена.
    :type string_bytes: bytes.
    :raise TypeError: string_bytes должен быть байтовой строкой.
    :return: Дополненная строка байтов с использованием схемы PKCS#5.
    :rtype: bytes.
    """
    if not isinstance(string_bytes, bytes):
        raise TypeError

    num_add = 8 - len(string_bytes)
    ans = string_bytes + bytes([num_add]) * num_add
    return ans


def feistel(r: str, key: str):
    """
    Выполняет функцию Фейстеля для одного раунда DES.

    :param r: Правый полу блок в двоичном формате.
    :type r: str.
    :param key: Ключ в двоичном формате для данного раунда.
    :type key: str.
    :raise TypeError: Возникает, когда Или r, или key не являются строками.
    :raise ValueError: Выбрасывает это исключение, когда длина r или key не 32 и 48 соответственно.
    :return: Результат применения функции Фейстеля в двоичном формате.
    :rtype: str.
    """
    if not isinstance(r, str) or not isinstance(key, str):
        raise TypeError
    if not (len(r) == 32) or not (len(key) == 48):
        raise ValueError

    e = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    er = "".join([r[i-1] for i in e])
    b = (bin(int(er, 2) ^ int(key, 2))[2:]).zfill(48)
    bls = [b[i:i + 6] for i in range(0, 48, 6)]
    s = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
          0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
          4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
          15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
         [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
          3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
          0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
          13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
         [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
          13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
          13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
          1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
         [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
          13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
          10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
          3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
         [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
          14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
          4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
          11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
         [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
          10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
          9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
          4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
         [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
          13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
          1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
          6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
         [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
          1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
          7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
          2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    new_bls = [""] * 8
    for i in range(8):
        a = int(bls[i][0] + bls[i][5], 2)
        k = int(bls[i][1:5], 2)
        new_bls[i] = (bin(s[i][a * 16 + k - 1])[2:]).zfill(4)
    p = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    final_b = "".join(new_bls)
    res = ""
    for i in p:
        res += final_b[i - 1]
    return res


def des(blok: bytes, key: bytes, mode="encrypt"):
    """
    Шифрует или расшифровывает блок данных с использованием алгоритма DES.

    :param blok: Блок данных, который необходимо зашифровать или расшифровать, должен быть в формате байтов.
    :type blok: bytes.
    :param key: Ключ для шифрования или расшифрования. Должен быть в формате байтов.
    :type key: bytes.
    :param mode: Режим работы функции. Может быть "encrypt" для шифрования
                 или "decrypt" для расшифрования. По умолчанию "encrypt".
    :raise TypeError: Возникает, если blok или key не того типа.
    :raise ValueError: Возникает, если длина blok или key не равна 64 и 56 соответственно,
                       или может возникнуть, если mode не принимает значение "encrypt" или "decrypt".
    :return: Зашифрованный или расшифрованный блок данных в двоичном формате.
             Возвращает строку, представляющую битовую последовательность
             зашифрованного или расшифрованного блока.
    :rtype: str.
    """
    if not isinstance(blok, bytes) or not isinstance(key, bytes):
        raise TypeError
    if not (len(blok) == 64) or not (len(key) == 56):
        raise ValueError
    if not (mode in ["encrypt", "decrypt"]):
        raise ValueError
    ip = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    keys = key_gen(key)
    blok = blok.hex()
    blok_bin = "".join((bin(int(blok[i:i+2], 16))[2:]).zfill(8) for i in range(0, len(blok), 2))
    blok_bin_transposition = ""
    for i in ip:
        blok_bin_transposition += blok_bin[i-1]
    ri = blok_bin_transposition[32:]
    li = blok_bin_transposition[:32]
    if mode == "encrypt":
        ri_last = ri
        for i in range(16):
            ri = (bin(int(li, 2) ^ int(feistel(ri, keys[i]), 2))[2:]).zfill(32)
            li = ri_last
            ri_last = ri
    elif mode == "decrypt":
        ri_last = ri
        for i in range(15, -1, -1):
            ri = (bin(int(li, 2) ^ int(feistel(ri, keys[i]), 2))[2:]).zfill(32)
            li = ri_last
            ri_last = ri
    reverse_blok = ri + li
    ip_rev = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
    fin_block = ""
    for i in ip_rev:
        fin_block += reverse_blok[i-1]
    return fin_block
