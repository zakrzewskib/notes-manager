from Crypto.Cipher import ARC4

def encryptMessage(message, password):
  cipher = ARC4.new(b"foobar")
  ciphertext = cipher.encrypt(b"to jest ciekawy tekst")
  return ciphertext

def decryptMessage(encryptedMessage, password):
  cipher = ARC4.new(b"foobar")
  decrypted = cipher.decrypt(encryptedMessage)
  return decrypted
