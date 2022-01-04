import os

def generateSecretKey():
	return os.urandom(32)