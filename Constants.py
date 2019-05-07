IV_LENGTH = 16
KEY_LENGTH = 32
KEY_BITS = 256
PAD_LENGTH = 128
RSA_KEYS_DIRECTORY = '.'
#RSA_PUBLIC_KEY_FILENAME = 'public_key.pem'
#RSA_PRIVATE_KEY_FILENAME = 'private_key.pem'
RSA_PUBLIC_KEYPATH = './public_key.pem'
RSA_PRIVATE_KEYPATH = './private_key.pem'
RSA_PUBLIC_EXPONENT = 65537 # we use 65537 because using anything else would reduce compatitlity with 
#software/hardware. a higher number would make the rsa operation slower and a lower number would make it faster
RSA_KEY_LENGTH = 2048

