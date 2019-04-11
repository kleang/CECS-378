import os
from cyptography.hazmat.primitives.ciphers.aead import AESCCM

IV_LENGTH = 16
KEY_LENGTH = 32
KEY_BITS = 256
PAD_LENGTH = 128

def Myencrypt(message, key):
        if (len(key) != KEY_BITS):
                raise ValueError("Key length must be 256 bits")
        padder =  padding.PKCS7(PAD_LENGTH).padder()
        messagePadded = padder.update(message)
        messagePadded += padder.finalize()
        IV = os.urandom(IV_LENGTH)
        encrypt = Cipher(algorithms.AES(key), modes.CBC(IV), backend = default_backend()).encryptor()
        C = encryptor.update(message) + encryptor.finalize()
        return C, IV

def MyfileEncrypt(filepath):
        splitPath = path.splitext(filepath)
        ext = splitPath[1]
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
        message = decryptor.update(ciphertext) + decryptor.finalize()
        unpad = padding.PKCS7(PAD_LENGTH).unpadder()
        message = unpadder.update(message)
        message = message + unpadder.finalize()
        return message

def MyfileDescrypt(filepath, key, IV, ext):
        file = open(filepath, "rb")
        content = file.read()
        file.close()
        message = MyDecrypt(content, key, IV)
        return message
