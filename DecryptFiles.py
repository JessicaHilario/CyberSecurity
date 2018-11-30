from myRsaEncrypt import *
import json, os, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from constants import *
from Myencrypt import *  
        
def DecryptFiles():

    # loop through all files in our cwd
    for root, dirs, files in os.walk(".", topdown=True):
        for name in files:
            file = os.path.join(root, name)

            # decrypt using information in the json file 
            if file.endswith('.json'):

                # open and load the json file
                jsonFile = open(file, 'r')
                data = json.load(jsonFile)
                jsonFile.close()

                # get values from json file
                RSACipher = base64.b64decode(data['RSACipher'])
                C = base64.b64decode(data['C'])
                IV = base64.b64decode(data['IV'])
                ext = data['ext']
                tag = base64.b64decode(data['tag'])

                # decrypt using the information and remove the json file 
                MyRSADecrypt(RSACipher, C, IV, tag, ext, KEYS_FILE_PATH +'/private_key.pem', file)
                os.remove(file)

DecryptFiles()
