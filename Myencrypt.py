import os
from cryptography.hazmat.primitives.ciphers import algorithms,modes, Cipher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def Myencrypt(message, key):
    """ generate 16 bytes IV, and encrypt the message using key and IV
    in CBC mode AES. return cipher and IV"""
    
    assert (len(key) >= 32),"key length is below 32 bits"
    backend = default_backend()
    
    # generate Initialization vector to be 16 bytes 
    IV = os.urandom(16)
    
    # padding using standard padding on block size 256
    pad = padding.PKCS7(256).padder()
    padded_data = pad.update(message.encode())
    padded_data += pad.finalize()

    # encrypting the with the padded data
    cipher_obj = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encrypt = cipher_obj.encryptor()
    cipher_text = encrypt.update(padded_data)
    cipher_text += encrypt.finalize()

    return cipher_text,IV


def MyfileEncrypt(filepath):
    """In this method, you'll generate a 32Byte key.
You open and read the file as a string. You then call
the above method to encrypt your file using the key you generated.
You return the cipher C, IV, key and the extension of the file (as a string).
"""
    
    # generate 32 byte key 
    key = os.urandom(32)

    # get extension of the file 
    path, file_ext = os.path.splitext(filepath)

    # read file
    file = open(filepath, 'r')
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
    
    print("the cipher recieved is   " + str(cipher))
    print()

    backend = default_backend()

    # creating decryption
    cipher_obj = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    decryptor = cipher_obj.decryptor()
    
    #cecrypting the message 
    message_padded = decryptor.update(cipher) + decryptor.finalize()

    #unpadding the message 
    unpadder = padding.PKCS7(256).unpadder()
    message = unpadder.update(message_padded) + unpadder.finalize()

    return message


def MyfileDecryptor(cipher, IV, key, ext):
    '''decrypt file and place original message back '''
    message = Mydecrypt(cipher, IV, key)
    print("message is  is " + str(message.decode("utf-8")))


    file_write = open('test'+ext, 'w')
    
    file_write.write(str(message.decode("utf-8")))
    file_write.close() # close the file 
    return message
    




cipher, IV, key, file_ext = MyfileEncrypt("test.txt")
input()
msg = MyfileDecryptor(cipher, IV, key, file_ext)


