import os
from constants import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

def Myencrypt(message, key):
	#Myencrypt encrypts the message using key and IV
	
	#Makes sure the key is at least 32
	assert(len(key)>=KEY_SIZE), "Key length is less than 32"
	backend = default_backend()
	
	#Generate an IV in 16 bytes
	IV = os.urandom(IV_SIZE)
	
	#Pads on a block size of 256
	padder = padding.PKCS7(BLOCK_SIZE).padder()
	padded = padder.update(message) + padder.finalize()
	
	#Encrypt with the padded data
	cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend) #Use CBC to start the encrypt
	encryptor = cipher.encryptor()
	ct = encryptor.update(padded) + encryptor.finalize()#Encrypt the message
	
	return ct, IV
	

def MyfileEncrypt(filepath):
	#MyfileEncrypt opens the file and read it as a string
	
	#Generate a key with 32 bits
	key = os.urandom(KEY_SIZE)
	
	#Get the extension of the file
	path, ext = os.path.split(filepath)
		
	#Read file
	file = open(filepath,'rb')
	file_read = file.read()
	file.close()
		
	#Encrypt the data
	C,IV = Myencrypt(file_read, key)
	
	#write to the file
	file_write = open(filepath,'wb')
	file_write.write(C)
	file_write.close()

	
	return C, IV, key, path, ext#json_data + " json.txt"


def Mydecrypt(C,IV, key):
	#Mydecrypt decrypts the cipher text using the IV and key
	
	#Make sure the key length is at least 32
	assert(len(key)>=KEY_SIZE), "Key length is less than 32"
	# create decryption 
	cipher_obj = Cipher(algorithms.AES(key), modes.CBC(IV), backend=default_backend())
	decryptor = cipher_obj.decryptor()
    
    # decrypt message
	message_padded = decryptor.update(C) + decryptor.finalize()
    
    # create unpadder and unpad message     
	unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
	message = unpadder.update(message_padded) + unpadder.finalize()
	
	return message

def MyfileDecrypt(C, IV, key, filename, ext):
	#MyfileDecrypt decrypts file and place original message back
	
	#Decrypt the data
	message = Mydecrypt(C,IV,key)
	
	#Writes to the same file
	jf = open(filename, "wb")
	jf.write(message)
	jf.close()
	
	return message

def MyencryptMAC(message, EncKey, HMACKey):
	
	#Encrypt the message and get the cipher and IV
	C, IV = Myencrypt(message, EncKey) #Encrypt
	
	#Then MAC
	tag = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #Returns an object of the class
	tag.update(C) # Bytes to hash then authenticate
	tag = tag.finalize() #Finalize the current context and return the message digest as bytes
	
	return C, IV, tag

def MyfileEncryptMAC(filepath):
	
	#Generate the HMAC Key and Encryption Key
	HMACKey = os.urandom(KEY_SIZE)
	EncKey = os.urandom(KEY_SIZE)
	
	#Get the extension of the file
	path, ext = os.path.split(filepath)
	
	#Read file
	file = open(filepath,'rb')
	message = file.read()
	file.close()
	
	#Encrypt the file and get the cipher, IV and key
	C, IV, tag = MyencryptMAC(message, EncKey, HMACKey)
	
	#write cipher to file
	file_write = open(filepath,'wb')
	file_write.write(C)
	file_write.close()
	
	return C, IV, tag, EncKey, HMACKey, ext
	
def MydecryptMAC(C, IV, tag, HMACKey, EncKey):

	assert(len(HMACKey) >= KEY_SIZE and  len(EncKey) >= KEY_SIZE),"Key length is less than 32"
	
	tagTest = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #Returns an object of the class
	
	tagTest.update(C) # Turn the byte to hash and authenticate
	tagTest.verify(tag) # Finalize and compare the digest to signature
	# Return error if signature does not match digest
	
	#Decrypt the message and get the message
	message = Mydecrypt(C, IV, EncKey)
	
	return message

def MyfileDecryptMAC(C, IV, tag, EncKey, HMACKey, filepath, ext):
	
	message = MydecryptMAC(C, IV, tag, HMACKey, EncKey) # decrpty cipher
	
	#Writes to the same file
	jf = open(filepath, "wb")
	jf.write(message)
	jf.close()
	return message
