import os
import Constants
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as assym_padding


#random Initial Vector generator
def generateIV():
    iv = os.urandom(constants.IV_LENGTH)
    return iv

#random Key generator
def generateKey():
    key = os.urandom(constants.KEY_LENGTH)
    return key



#generating private key and public key 
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
    return