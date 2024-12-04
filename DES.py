def key_gen(key56: bytes):
    key64 = ""
    bin_key56 = (bin(int(key56.hex(), 16))[2:]).zfill(56)
    ls = [bin_key56[i:i + 7] for i in range(0, 56, 7)]
    for num in ls:
        key64 += num + "0" if num.count("1") % 2 == 1 else "1"
    ci = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
          10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
    di = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
          14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    sd = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    fin = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    lsk = [""] * 16
    for i in range(0, 16):
        ci = ci[sd[i]:] + ci[:sd[i]]
        di = di[sd[i]:] + di[:sd[i]]
        prom_key = ""
        for j in ci + di:
            prom_key += key64[j - 1]
        for j in fin:
            lsk[i] += prom_key[j - 1]
    return lsk


def pkcs5(string_bytes: bytes):
    num_add = 8 - len(string_bytes)
    ans = string_bytes + bytes(num_add) * num_add
    return ans








