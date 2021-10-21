import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

second_key = b'MyEncryptionKey2'
initialization_vector = b'1234567891011120'
block_size = 16


def xor_for_bytes(bytes_a, bytes_b):
    """
    Applies XOR operation between two strings of bytes
    :param bytes_a: first string of bytes
    :param bytes_b: second string of bytes
    :return: bytes_a XOR bytes_b
    """
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


def encrypt_block(input_bytes, key):
    """
    Encrypt a single block of block_size bytes using AES encryption
    :param input_bytes: string of block_size bytes to encrypt
    :param key: encryption key
    :return: encrypted string of bytes
    """
    return AES.new(key, AES.MODE_ECB).encrypt(input_bytes)


def decrypt_block(input_bytes, key):
    """
    Decrypt a single block of block_size bytes using AES Decryption
    :param input_bytes: string of block_size bytes to decrypt
    :param key: decryption key
    :return: decrypted string of bytes
    """
    return AES.new(key, AES.MODE_ECB).decrypt(input_bytes)


def ecb_encrypt(input_bytes, key):
    """
    This method is used to encrypt in ECB mode
    :param input_bytes: String of bytes to encrypt
    :param key: The encryption key
    :return: The cypher (encrypted message)
    """
    cypher_text = bytes()
    block = input_bytes[:block_size]
    while len(input_bytes) > 0:
        cypher_text += encrypt_block(block, key)
        input_bytes = input_bytes[block_size:]
        block = input_bytes[:block_size]
    return cypher_text


def ofb_encrypt(input_bytes, key, iv):
    """
    This method is used to encrypt in OFB mode
    :param input_bytes: String of bytes to encrypt
    :param key: The encryption key
    :param iv: The initialization vector used for encryption
    :return: The cypher (encrypted message)
    """
    cypher_text = bytes()
    block = input_bytes[:block_size]
    while len(input_bytes) > 0:
        enc_iv = encrypt_block(iv, key)
        cypher_text += xor_for_bytes(enc_iv, block)
        input_bytes = input_bytes[block_size:]
        block = input_bytes[:block_size]
        iv = enc_iv
    return cypher_text


def ecb_decrypt(input_bytes, key):
    """
    This method is used to decrypt in ECB mode
    :param input_bytes: String of bytes to decrypt
    :param key: The decryption key
    :return: Decrypted message
    """
    decrypted_text = bytes()
    block = input_bytes[:block_size]
    while len(input_bytes) > 0:
        decrypted_text += decrypt_block(block, key)
        input_bytes = input_bytes[block_size:]
        block = input_bytes[:block_size]
    return decrypted_text


def ofb_decrypt(input_bytes, key, iv):
    """
    This method is used to decrypt in OFB mode
    :param input_bytes: String of bytes to decrypt
    :param key: The decryption key
    :param iv: The initialization vector used for decryption
    :return: The cypher (decrypted message)
    """
    cypher_text = bytes()
    block = input_bytes[:block_size]
    while len(input_bytes) > 0:
        enc_iv = encrypt_block(iv, key)
        cypher_text += xor_for_bytes(enc_iv, block)
        input_bytes = input_bytes[block_size:]
        block = input_bytes[:block_size]
        iv = enc_iv
    return cypher_text


def encrypt(input_bytes, method, key, iv=None):
    """
    This method is used to choose the encryption type
    :param input_bytes: String of bytes to encrypt
    :param method: Type of encryption
    :param key: The encryption key
    :param iv: The initialization vector used for (OFB) encryption
    :return: The cypher (encrypted message)
    """
    if method == "ECB":
        return ecb_encrypt(pad(input_bytes, block_size), key)
    elif method == "OFB":
        return ofb_encrypt(pad(input_bytes, block_size), key, iv)


def decrypt(input_bytes, method, key, iv=None):
    """
    This method is used to choose the decryption type
    :param input_bytes: String of bytes to decrypt
    :param method: Type of decryption
    :param key: The decryption key
    :param iv: The initialization vector used for (OFB) decryption
    :return: Decrypted message
    """
    if method == "ECB":
        return unpad(ecb_decrypt(input_bytes, key), block_size)

    elif method == "OFB":
        return unpad(ofb_decrypt(input_bytes, key, iv), block_size)


s = socket.socket()
port = 9990
s.connect(('127.0.0.1', port))

operation_mode = s.recv(512).decode('ascii')
print("Current operation mode is : " + operation_mode)
encrypted_key = s.recv(512)
print("Encrypted Key is " + str(encrypted_key))
print("Decrypting...")
enc_key = decrypt_block(encrypted_key, second_key)
print("Decrypted key is " + enc_key.decode('ascii'))
s.send("Let's communicate".encode('ascii'))
file_content = s.recv(512)
print("Message from node A is :" + str(file_content))
print("Decrypted message is:")
print(decrypt(file_content, operation_mode, enc_key, initialization_vector).decode('ascii'))
s.close()
