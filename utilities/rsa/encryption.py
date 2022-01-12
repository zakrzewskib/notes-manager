from Crypto.PublicKey import RSA
# keys = RSA.generate(2048)
# publicKey = keys.public_key().export_key()
# privateKey = keys.export_key()

# with open('key.pub', 'wb') as f:
# 	f.write(publicKey)

# with open('key', 'wb') as f:
# 	f.write(privateKey)

# or use https://travistidwell.com/jsencrypt/demo/

from Crypto.Cipher import PKCS1_OAEP
def encryptWithSomeonesPublicKey(publicKey, data):
  cipher = PKCS1_OAEP.new(RSA.import_key(publicKey))
  message = data.encode()
  encrypted = cipher.encrypt(message) 
  return encrypted

def decryptWithPrivateKey(privateKey, encrypted):
  cipher = PKCS1_OAEP.new(RSA.import_key(privateKey))
  decrypted = cipher.decrypt(encrypted)
  return decrypted.decode()

# f = open('key.pub', 'rb')
# public = f.read()

# f = open('key', 'rb')
# private = f.read()

# ciphertext = encryptWithSomeonesPublicKey(public)
# print(decryptWithPrivateKey(private, ciphertext))