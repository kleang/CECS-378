import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as paddings
import json
import re

KEY_LENGTH_BITS = 256
KEY_LENGTH_BYTES = 32
MESSAGE_LENGTH_BITS = 128
IV_LENGTH_BITS = 16
ENC_HMAC_KEY_LENGTH = 64
RSA_PUBLIC_KEY = ".\PublicKey.pem"
RSA_PRIVATE_KEY = ".\PrivateKey.pem"
PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048

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
        
        def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
        C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(filepath)

        with open(RSA_Publickey_filepath, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                        key_file.read(),
                        backend = default_backend()
                )

        key = EncKey + HMACKey

        RSACipher = public_key.encrypt(
                key,
                paddings.OAEP(
                        mgf = paddings.MGF1(algorithm = hashes.SHA256()),
                        algorithm = hashes.SHA256(),
                        label = None
                )
        )

        return RSACipher, C, IV, tag, ext

def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
        key_file = open(RSA_Privatekey_filepath, "rb")
        private_key = serialization.load_pem_private_key(
                key_file.read(),
                password = None,
                backend = default_backend()
        )
        key_file.close()
        key = private_key.decrypt(RSACipher,
                paddings.OAEP(
                        mgf = paddings.MGF1(algorithm = hashes.SHA256()),
                        algorithm = hashes.SHA256(),
                        label = None
                )
        )
        EncKey = key[0:KEY_LENGTH_BYTES]
        HMACKey = key[KEY_LENGTH_BYTES:ENC_HMAC_KEY_LENGTH]
        message = MyDecryptMAC(C, IV, tag, EncKey, HMACKey)
        return message

def MyFileRSAEncrypt(filepath, RSA_Publickey_filepath):
        private_key, public_key = LoadKeys()
        RSACipher, C, IV, tag, ext = MyRSAEncrypt(filepath, RSA_Publickey_filepath)
        name, ext = os.path.splitext(filepath)
        jsonFile = name + ".json"
        jsonContent = {"RSACipher":RSACipher.decode("cp437"),
                "C":C.decode("cp437"),
                "IV":IV.decode("cp437"),
                "tag":tag.decode("cp437"),
                "ext":ext
        }
        file = open(jsonFile, "w")
        file.write(json.dumps(jsonContent))
        file.close()
        os.remove(filepath)
        return RSACipher, C, IV, tag, ext
        
        def MyFileRSADecrypt(filepath, RSA_Privatekey_filepath):
        file = open(filepath, "r")
        content = file.read()
        file.close()

        os.remove(filepath)
        jsonContent = json.loads(content)

        RSACipher = jsonContent["RSACipher"].encode("cp437")
        C = jsonContent["C"].encode("cp437")
        IV = jsonContent["IV"].encode("cp437")
        tag = jsonContent["tag"].encode("cp437")
        ext = jsonContent["ext"]

        name = os.path.splitext(filepath)[0]
        filepath = name + ext

        message = MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath)

        file = open(filepath, "wb")
        file.write(message)
        file.close()
        return message
        def GenerateKeys():
        private_key = rsa.generate_private_key(
                public_exponent = PUBLIC_EXPONENT,
                key_size = KEY_SIZE,
                backend = default_backend()
        )
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_file = open(RSA_PRIVATE_KEY, "wb")
        private_key_file.write(private_pem)
        private_key_file.close()
        public_key_file = open(RSA_PUBLIC_KEY, "wb")
        public_key_file.write(public_pem)
        public_key_file.close()
        return private_key, public_key
        
        def LoadKeys():
        PublicExists = os.path.isfile(RSA_PUBLIC_KEY)
        PrivateExists = os.path.isfile(RSA_PRIVATE_KEY)
        if (not PublicExists) or (not PrivateExists):
                return GenerateKeys()
        else:
                private_file = open(RSA_PRIVATE_KEY, "rb")
                private_key = serialization.load_pem_private_key(
                        private_file.read(),
                        password = None,
                        backend = default_backend()
                )
                private_file.close()
                public_file = open(RSA_PUBLIC_KEY, "rb")
                public_key = serialization.load_pem_public_key(
                        public_file.read(),
                        backend = default_backend()
                )
                public_file.close()
                return private_key, public_key

#filepath = "test.txt"
#MyFileRSAEncrypt(filepath, RSA_PUBLIC_KEY)
filepath = "test.json"
message = MyFileRSADecrypt(filepath, RSA_PRIVATE_KEY)
        
