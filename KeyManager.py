import random
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

second_key = b'MyEncryptionKey2'
block_size = 16


def encrypt_block(input_bytes, key):
    """
    Encrypt a single block of 16 bytes using AES encryption
    :param input_bytes: string of 16 bytes to encrypt
    :param key: encryption key
    :return: encrypted string of bytes
    """
    return AES.new(key, AES.MODE_ECB).encrypt(input_bytes)


def generate_key():
    """
    Generates a new random key of block_size bytes and applies AES encryption using second_key
    :return: Encrypted generated key
    """
    key = ''.join([chr(random.randint(0, 0x10)) for _ in range(block_size)])
    return AES.new(second_key, AES.MODE_ECB).encrypt(pad((key.encode('ascii')), block_size))


s = socket.socket()
port = 9990
s.connect(('127.0.0.1', port))

encryption_key = generate_key()
print(encryption_key)

print(s.recv(512).decode())
print('Sending Encrypted key')
s.send(encryption_key)
s.close()
