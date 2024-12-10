def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha(): 
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char 
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    return caesar_encrypt(encrypted_text, -shift)
