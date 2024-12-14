def validate_key(key: str):
    """Checks that the key consists only of letters.

    :param key: The key for encryption.
    :type key: str
    :raises ValueError: If the key contains invalid characters.
    """
    if not key.isalpha():
        raise ValueError("The key must consist only of letters.")


def validate_text(text: str):
    """Checks that the text consists only of letters.

    :param text: Text for encryption or decryption.
    :type text: str
    :raises ValueError: If the text contains invalid characters.
    """
    if not text.isalpha():
        raise ValueError("The text should consist only of letters.")


def viginer_encrypt(plaintext: str, key: str) -> str:
    """Encrypts the text using the Vigener key.

    :param plaintext: Plaintext for encryption. It should consist only of letters.
    :type plaintext: str
    :param key: The key for encryption. It should consist only of letters.
    :type key: str
    :return: Encrypted text.
    :rtype: str
    :raises ValueError: If the plaintext or key contains invalid characters.
    """
    validate_key(key)
    validate_text(plaintext)

    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = []
    key_length = len(key)

    for i, char in enumerate(plaintext):
        shift = ord(key[i % key_length]) - ord('A')
        encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        ciphertext.append(encrypted_char)

    return ''.join(ciphertext)


def viginer_decrypt(ciphertext: str, key: str) -> str:
    """Decrypts the text using the Vigener key.

    :param ciphertext: Encrypted text for decryption. It should consist only of letters.
    :type ciphertext: str
    :param key: The decryption key. It should consist only of letters.
    :type key: str
    :return: Plaintext.
    :rtype: str
    :raises ValueError: If the encrypted text or key contains invalid characters.
    """
    validate_key(key)
    validate_text(ciphertext)

    ciphertext = ciphertext.upper()
    key = key.upper()
    decrypted_text = []
    key_length = len(key)

    for i, char in enumerate(ciphertext):
        shift = ord(key[i % key_length]) - ord('A')
        decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
        decrypted_text.append(decrypted_char)

    return ''.join(decrypted_text)
