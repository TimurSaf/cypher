def caesar_encrypt(text, shift):
    """Encrypts the given text using the Caesar cipher with the specified shift.

    :param text: The text to be encrypted. Must be a string.
    :type text: str
    :param shift: The number of positions each letter in the text will be shifted.
    :type shift: int
    :raises TypeError: If text is not a string or shift is not an integer.
    :return: The encrypted text, with letters shifted by the specified amount.
    :rtype: str
    """
    if type(text) != str:
        raise TypeError
    
    if type(shift) != int:
        raise TypeError
    
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
    """Decrypts the given text that was encrypted using the Caesar cipher.

    :param encrypted_text: The text to be decrypted. Must be a string.
    :type encrypted_text: str
    :param shift: The number of positions each letter in the text will be shifted back.
    :type shift: int
    :raises TypeError: If encrypted_text is not a string or shift is not an integer.

    :return: The decrypted text, with letters shifted back by the specified amount.
    :rtype: str
    """
    
    if type(encrypted_text) != str:
        raise TypeError
    
    if type(shift) != int:
        raise TypeError
    
    return caesar_encrypt(encrypted_text, -shift)
def caesar_encrypt(text, shift):
    """Encrypts the given text using the Caesar cipher with the specified shift.

    :param text: The text to be encrypted. Must be a string.
    :type text: str
    :param shift: The number of positions each letter in the text will be shifted.
    :type shift: int
    :raises TypeError: If text is not a string or shift is not an integer.
    :return: The encrypted text, with letters shifted by the specified amount.
    :rtype: str
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    if not isinstance(shift, int):
        raise TypeError("shift must be an integer")

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
    """Decrypts the given text that was encrypted using the Caesar cipher.

    :param encrypted_text: The text to be decrypted. Must be a string.
    :type encrypted_text: str
    :param shift: The number of positions each letter in the text will be shifted back.
    :type shift: int
    :raises TypeError: If encrypted_text is not a string or shift is not an integer.
    :return: The decrypted text, with letters shifted back by the specified amount.
    :rtype: str
    """
    if not isinstance(encrypted_text, str):
        raise TypeError("encrypted_text must be a string")

    if not isinstance(shift, int):
        raise TypeError("shift must be an integer")

    return caesar_encrypt(encrypted_text, -shift)
