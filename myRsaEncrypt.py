import json,os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from constants import *
from Myencrypt import *
from  cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1


def generateRSAKeys(KEYS_FILE_PATH):
    ''' Generate a new a pair of RSA public key and
        RSA private key if one is not found'''


    private_key_exists = False      
    # Loop through the files in the given directory look for private key
    for file in os.listdir(KEYS_FILE_PATH):     
        # Checks if there exists a file with extension .pem
        if file.endswith(".pem") and "private" in file:
            private_key_exists = True
            
    public_key_exists = False      
    # Loop through the files in the given directory look for private key
    for file in os.listdir(KEYS_FILE_PATH):     
        # Checks if there exists a file with extension .pem
        if file.endswith(".pem") and "public" in file:
            public_key_exists = True

    keys_exist = public_key_exists and private_key_exists


    # If keys do not exist create create it 
    if(not keys_exist): 
        # generate the RSA private key
        private_key = rsa.generate_private_key(public_exponent = FERMAT_PRIME,
                                               key_size = RSA_KEY_SIZE,
                                               backend=default_backend())

        
        # serialize the private key  
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())

        # serialize the public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)


        # write the keys to disk
        file_write = open(KEYS_FILE_PATH +"/private_key.pem", "wb")
        file_write.write(private_pem)
        file_write.close()

        file_write = open(KEYS_FILE_PATH +"/public_key.pem", "wb")
        file_write.write(public_pem)
        file_write.close()



def MyRSAEncrypt(filepath, RSA_publickey_filepath):
    ''' Call MyfileEncryptMac on a file. Concatenate the Enkey and HMAC from result.
        Encrypt the key variable in RSA in OAEP padding mode'''
    # Encrypt and hmac file
    C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC(filepath)    

    # make rsa encryption object and load the public key
    with open(RSA_publickey_filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend())

    # encrypt key=EncKey+HmacKey using rsa public key in OAEP padding mode
    key = EncKey + HMACKey
    RSACipher = public_key.encrypt(key, OAEP(mgf=MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))
    return RSACipher, C, IV, ext, tag


def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath, filepath):
    ''' Decrypt the key variable. And encrypt the message.'''
    # make decryptor object 
    with open(RSA_Privatekey_filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend())

    # decrypt RSACipher
    key = private_key.decrypt(RSACipher,
                                  OAEP(mgf=MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None))

    # get the encryption key and HMAC key from the concatenated key
    EncKey = key[0:32]
    HMACKey = key[len(EncKey):]

    # decrypt the message 
    MyfileDecryptMAC(C, IV, tag, EncKey, HMACKey, filepath, ext)
    

generateRSAKeys(KEYS_FILE_PATH)
filepath = "test.png"
RSACipher, C, IV, ext, tag = MyRSAEncrypt(filepath, "public_key.pem")
input("Press enter")
MyRSADecrypt(RSACipher, C, IV, tag, ext, "private_key.pem", filepath)

