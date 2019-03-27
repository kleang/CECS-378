from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac

KEY_LENGTH_BITS = 256
KEY_LENGTH_BYTES = 32
MESSAGE_LENGTH_BITS = 128
IV_LENGTH_BITS = 16

#(C,IV,tag) = MyencryptMAC(message, EncKey, HMACKey)
def MyencryptMAC(message,EncKey, HMACKey):
        padder = padding.PKCS7(MESSAGE_LENGTH_BITS).padder
        padEnc = padder.update(message)
        padEnc += padder.finalize()

        IV = os.urandom(IV_LENGTH_BITS)
  #create a cipher that combines the AES algorithm and CBC mode
        encryptor = Ciper(algorithms.AES(EncKey),modes.CBC(IV), backend = default)
        cipherText = encryptor.update(padEnc) + encryptor.finalize()

        #create HMAC tag(SHA256) and update tag with  cipherTex
        t = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default_backend())
        t.update(cipherText)
        tag = t.finalize()

return cipherText, IV, tag


def MyDecryptMAC(C, IV, tag, encKey, HMACKey):
        #create tag and update C with hash
        h_tag = hmac.HMAC(HMACKEY, hashes.SHA256(), backend = default.backend())
        h_tag.update(C)
        h_tag.verify(tag)

        #create decryptor
  decryptor = Cipher(algorithms.AES(encKey), modes.CBC(IV), backend = def$
        message = decyptor.update(C) + decryptor.finalize()

        unpadder = padding.PKCS7(MESSAGE_LENGTH_BITS).unpadder()
        message = unpadder.update(message)
        message = message + unpadder.finalize()

        return message


def MyFileEncryptMAC(filepath):
        splitFilePath = path.splitext(filepath)
        ext = splitPath[1]
        file = open(filepath, "rb")
        fileBytes = file.read()

        key = os.urandom(KEY_LENGTH_BYTES)
        cipherText, IV , tag = MyEncryptMAC(fileBytes, EncKey, HMACKey)

        return cipherText, IV, EncKey, HMACKey


def MyFileDecryptMAC(pathToFile, fileName, C, IV, tag, EncKey, HMACKey, ext):
        verificationTag = hmac.HMAC(HMACKey, hashes.SHA256(), backend = default$
        verificationTag.update(C)
        verificationTag.verify(tag)

        message = MydecryptMAC(C, IV, tag, EncKey, HMACKey)


