import os
import Constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as assym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, utils
import json
import re


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

#verification of existence of RSA keys
def verify_RSA_keys():
    if (not os.path.isfile(Constants.RSA_PUBLIC_KEYPATH)) or (not os.path.isfile(Constants.RSA_PRIVATE_KEYPATH)):
        keyGen.RSA_generate_keys()
        print("At least one of the keys not found.\nGenerating new keys...")
    else:
        print("Keys found")
    return

def RSA_generate_keys():
    #getting private key
    private_key = rsa.generate_private_key(
        public_exponent = Constants.RSA_PUBLIC_EXPONENT,
        key_size = Constants.RSA_KEY_LENGTH,
        backend = default_backend()
    )
    
    #getting public key
    public_key = private_key.public_key()
    
    #serializing keys to pem
    prvk_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )
        
    pubk_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    pubk_pem.splitlines()[0]
    prvk_pem.splitlines()[0]
    
    #writing private key to pem file
    file = open(Constants.RSA_PRIVATE_KEYPATH, 'wb')
    file.write(prvk_pem)
    file.close()

    #writing public key back to pem
    file = open(Constants.RSA_PUBLIC_KEYPATH, 'wb')
    file.write(pubk_pem)
    file.close()
    return public_key, private_key

def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    verify_RSA_keys()

    #encrypting file
    C, IV, tag, enc_key, HMACKey, ext = MACEncrypt.MyFileEncryptMAC(filepath)
    
    #reading in / loading pem public key
    file = open(RSA_Publickey_filepath, 'rb')
    public_key = serialization.load_pem_public_key(
        file.read(),
        backend = default_backend()
    )
    file.close()

    #concatenating encoding and hmac keys
    key = enc_key + HMACKey
    
    #encrypting key variable
    RSACipher = public_key.encrypt(
        key,
        assym_padding.OAEP(
            mgf = assym_padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    
    return RSACipher, C, IV, tag, ext

def MyFileRSAEncrypt(filepath, RSA_PubKey_filepath):
        private_key, public_key = LoadKeys()
        RSACipher, C, IV, tag, ext = MyRSAEncrypt(filepath, RSA_PubKey_filepath)
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
        
        
#filepath is the path to write the file to
def MyRSADecrypt(filepath, RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    
    #read in private key
    file = open(RSA_Privatekey_filepath, 'rb')
    private_key = serialization.load_pem_private_key(
        file.read(),
        password = None,
        backend = default_backend()
    )
    file.close()

    #decryption
    RSA_enc_HMAC_key = private_key.decrypt(
        RSACipher,
        assym_padding.OAEP(
            mgf = assym_padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    #split RSA key into enc_key and HMACKey
    enc_key = RSA_enc_HMAC_key[:constants.KEY_LENGTH]
    HMACKey = RSA_enc_HMAC_key[constants.KEY_LENGTH:]
    
    #writing out to file
    MACEncrypt.MyFileDecryptMAC(filepath, C, IV, tag, enc_key, HMACKey, ext)
    return

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

filepath = "test.json"
MyFileRSAEncrypt(filepath, RSA_PUBLIC_KEYPATH)
#message = MyFileRSADecrypt(filepath, RSA_PRIVATE_KEY)

