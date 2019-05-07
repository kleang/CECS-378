import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

IV_LENGTH = 16
KEY_LENGTH = 32
KEY_BITS = 256
PAD_LENGTH = 128

def MyEncrypt(message, key):
        if (len(key) < KEY_LENGTH):
                raise ValueError("Key length is less than 32 bytes")
        padder =  padding.PKCS7(PAD_LENGTH).padder()
        messagePadded = padder.update(message)
        messagePadded += padder.finalize()
        IV = os.urandom(IV_LENGTH)
        encrypt = Cipher(algorithms.AES(key), modes.CBC(IV), backend = default_backend()).encryptor()
        C = encrypt.update(messagePadded) + encrypt.finalize()
        return C, IV

def MyFileEncrypt(filepath):
        key = os.urandom(KEY_LENGTH)
        name, ext = os.path.splitext(filepath)
        file = open(filepath, "rb")
        fileBytes = file.read()
        file.close()
        C, IV = MyEncrypt(fileBytes, key)
        file = open(filepath, "wb")
        file.write(C)
        file.close()
        return C, IV, key, ext

def MyDecrypt(ciphertext, key, IV):
        decrypt = Cipher(algorithms.AES(key), modes.CBC(IV), backend = default_backend()).decryptor()
        message = decrypt.update(ciphertext) + decrypt.finalize()
        unpad = padding.PKCS7(PAD_LENGTH).unpadder()
        message = unpad.update(message) + unpad.finalize()
        return message

def MyFileDecrypt(filepath, key, IV, ext):
        file = open(filepath, "rb")
        content = file.read()
        file.close()
        message = MyDecrypt(content, key, IV)
        file = open(filepath, "wb")
        file.write(message)
        file.close()
        return message, key, IV

filepath = "text.txt"

C, IV, key, ext = MyFileEncrypt(filepath)
MyFileDecrypt(filepath, key, IV, ext)