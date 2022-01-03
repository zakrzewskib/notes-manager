from Crypto.Cipher import ARC4

def encryptMessage(message, password):
  cipher = ARC4.new(str.encode(password))
  ciphertext = cipher.encrypt(str.encode(message))
  return ciphertext

def decryptMessage(encryptedMessage, password):
  cipher = ARC4.new(str.encode(password))
  decrypted = cipher.decrypt(encryptedMessage)
  return decrypted.decode()

