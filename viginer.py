def vignere_encrypt(plaintext, key):
    encrypted_text = ""
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    
    return encrypted_text

def vignere_decrypt(encrypted_text, key):
    decrypted_text = ""
    key_length = len(key)
    
    for i, char in enumerate(encrypted_text):
        if char.isalpha():
            shift = ord(key[i % key_length].upper()) - ord('A')
            shift_base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - shift_base - shift) % 26 + shift_base)
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    
    return decrypted_text
