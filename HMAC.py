import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac

KEY_LENGTH_BITS = 256
KEY_LENGTH_BYTES = 32
MESSAGE_LENGTH_BITS = 128
IV_LENGTH_BITS = 16

#(C,IV,tag) = MyencryptMAC(message, EncKey, HMACKey)
def MyEncryptMAC(message,EncKey, HMACKey):
        if (len(EncKey) < KEY_LENGTH_BYTES):
                raise ValueError("Key length is less than 32 bytes")
        padder = padding.PKCS7(MESSAGE_LENGTH_BITS).padder()
        messagePadded = padder.update(message)
        messagePadded += padder.finalize()

        IV = os.urandom(IV_LENGTH_BITS)
#create a cipher that combines the AES algorithm and CBC mode
        encrypt = Cipher(algorithms.AES(EncKey),modes.CBC(IV), backend = default_backend()).encryptor()
        C = encrypt.update(messagePadded) + encrypt.finalize()

        #create HMAC tag(SHA256) and update tag with  cipherTex
        t = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
        t.update(C)
        tag = t.finalize()

        return C, IV, tag


def MyDecryptMAC(C, IV, tag, EncKey, HMACKey):
        #create tag and update C with hash
        t = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
        t.update(C)
       # t.verify(tag)

        #create decryptor
        decrypt = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend = default_backend()).decryptor()
        message = decrypt.update(C) + decrypt.finalize()

        unpadder = padding.PKCS7(MESSAGE_LENGTH_BITS).unpadder()
        message = unpadder.update(message) 
        message += unpadder.finalize()

        return message


def MyFileEncryptMAC(filepath):
        name, ext = os.path.splitext(filepath)

        file = open(filepath, "rb")
        fileBytes = file.read()
        file.close()

        key = os.urandom(KEY_LENGTH_BYTES)
        HMACKey = os.urandom(KEY_LENGTH_BYTES)
        cipherText, IV , tag = MyEncryptMAC(fileBytes, key, HMACKey)

        file = open(filepath, "wb")
        file.write(cipherText)
        file.close()

        return cipherText, IV, tag, key, HMACKey, ext


def MyFileDecryptMAC(filepath, IV, tag):
        EncKey = os.urandom(KEY_LENGTH_BYTES)
        HMACKey= os.urandom(KEY_LENGTH_BYTES)
        
        file = open(filepath, "rb")
        content = file.read()
        file.close()

        message = MyDecryptMAC(content, IV, tag, key, HMACKey)

        file = open(filepath, "wb")
        file.write(message)
        file.close()

        return message

filepath = "pup.jpg"
 
cipherText, IV, tag, key, HMACKey, ext = MyFileEncryptMAC(filepath)
MyFileDecryptMAC(filepath, IV, tag)
