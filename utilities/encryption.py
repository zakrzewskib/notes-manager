from Crypto.Cipher import AES

from Crypto.Util.Padding import pad, unpad
BLOCK_SIZE = 32


def encryptMessage(data, password):
    key = password.encode()
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(pad(data.encode(), BLOCK_SIZE))


def decryptMessage(ciphertext, password):
    key = password.encode()
    aes = AES.new(key, AES.MODE_ECB)
    return unpad(aes.decrypt(ciphertext), BLOCK_SIZE).decode()


# ciphertext = encryptMessage('secret message', 'passwordpassword')
# print(decryptMessage(ciphertext, 'passwordpassword'))
