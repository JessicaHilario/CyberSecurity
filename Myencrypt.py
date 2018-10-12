import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def Myencrypt(message, key):
    """ generate 16 bytes IV, and encrypt the message using key and IV
    in CBC mode AES. return cipher and IV"""

    assert (len(key) >= 32),"key length is below 32 bits"
    
    # generate Initialization vector to be 16 bytes 
    IV = os.urandom(16)

    cipher_obj = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())

    encrypt = cipher_obj.encryptor()

    # padding using standard padding on block size 256
    pad = padding.PKCS7(256).padder()

    padded_data = pad.update(message)
    padded_data += pad.finalize()

    # encrypting the with the padded data
    cipher_text = encrypt.update(padded_data)
    cipher_text += encrypt.finalize()

    return cipher_text,IV


def MyfileEncrypt(filepath):
    """In this method, you'll generate a 32Byte key.
    You open and read the file as a string. You then call
    the above method to encrypt your file using the key you generated.
    You return the cipher C, IV, key and the extension of the file (as a string)."""

    # generate 32 byte key 
    key = os.urandom(32)

    # get the file extension
    path, file_ext = os.path.splitext(filepath)

    # open and read file
    file = open(filepath, 'rb')
    file_in = file.read()
    
    print("message is " + str(file_in))
    print()

    file.close() # close the file 
    
    #generate cipher and return IV for the file 
    cipher,IV = Myencrypt(file_in, key)

    #write to the file
    file_write = open(filepath, 'wb')
    file_write.write(cipher)


    print("cipher is " +str(cipher))
    print()
    file_write.close()
    return cipher, IV, key, file_ext


def Mydecrypt(cipher, IV, key):
    """ decrypts the cipher text using IV and key"""

    # create decryption 
    cipher_obj = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher_obj.decryptor()
    
    # decrypt message
    message_padded = decryptor.update(cipher) + decryptor.finalize()
    
    # create unpadder and unpad message     
    unpadder = padding.PKCS7(256).unpadder()
    message = unpadder.update(message_padded) + unpadder.finalize()

    return message


def MyfileDecryptor(cipher, IV, key, file):
    '''decrypt file and place original message back '''

    # decrypt the message 
    message = Mydecrypt(cipher, IV, key)
    print("message is  is " + str(message))
    print()

    # write the message back to the file
    file_write = open(file, 'wb')
    file_write.write(message) 
    file_write.close() # close the file 
    return message
    

file = "test.txt"
cipher, IV, key, file_ext = MyfileEncrypt(file)
input()

msg = MyfileDecryptor(cipher, IV, key, file)
