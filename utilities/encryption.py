# I want to use symmetric encryption - use the same password/key for encryption and decryption

# I used ARC4 as first algorithm to encrypt notes, but it is suggested to use more secure AES
# However in AES key need to be size of 16 bytes, and for now I cannot make it work

from Crypto.Cipher import ARC4

def encryptMessage(message, password):
  cipher = ARC4.new(str.encode(password))
  ciphertext = cipher.encrypt(str.encode(message))
  return ciphertext

def decryptMessage(encryptedMessage, password):
  cipher = ARC4.new(str.encode(password))
  decrypted = cipher.decrypt(encryptedMessage)
  return decrypted.decode()

print(decryptMessage(encryptMessage('secret message', 'password'), 'password'))