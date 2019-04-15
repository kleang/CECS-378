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
        padEnc = padder.update(message)
        padEnc += padder.finalize()

        IV = os.urandom(IV_LENGTH_BITS)
  #create a cipher that combines the AES algorithm and CBC mode
        encryptor = Cipher(algorithms.AES(EncKey),modes.CBC(IV), backend = default_backend()).encryptor()
        cipherText = encryptor.update(padEnc) + encryptor.finalize()

        #create HMAC tag(SHA256) and update tag with  cipherTex
        t = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
        t.update(cipherText)
        tag = t.finalize()

        return cipherText, IV, tag


def MyDecryptMAC(C, IV, tag, encKey, HMACKey):
        #create tag and update C with hash
        h_tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
        h_tag.update(C)
        h_tag.verify(tag)

        #create decryptor
        decryptor = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend = default_backend()).decryptor()
        message = decryptor.update(C) + decryptor.finalize()

        unpadder = padding.PKCS7(MESSAGE_LENGTH_BITS).unpadder()
        message = unpadder.update(message)
        message = message + unpadder.finalize()

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


def MyFileDecryptMAC(filepath, IV, tag, EncKey, HMACKey):
        file = open(filepath, "rb")
        content = file.read()
        file.close()

        message = MyDecryptMAC(content, IV, tag, EncKey, HMACKey)

        file = open(filepath, "wb")
        file.write(message)
        file.close()

        return message

filepath = "text.txt"
C, IV, tag, key, HMACKey, ext = MyFileEncryptMAC(filepath)
MyFileDecryptMAC(filepath, IV, tag, key, HMACKey)
