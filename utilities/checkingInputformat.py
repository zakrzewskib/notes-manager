def checkUsername(input):
	for i, character in enumerate(input):
		if ord(character) < 48 or (ord(character) > 57 and ord(character) < 65) or (ord(character) > 90 and ord(character) < 96) or ord(character) > 122:
			return False
	return True

# print(checkUsername("UsernameBob")) # True
# print(checkUsername("Us3r12#%!"))
# print(checkUsername("Username@"))
# print(checkUsername('<img src="..." onerror="javascript:alert(1)">'))
# print((checkUsername("bob' OR username='alice")))
# print((checkUsername("OK'),('user13', (SELECT VERSION())) -- ")))
# print((checkUsername("OK'),('user13', (SELECT VERSION())) -- ")))

def checkEmail(input):
	for i, character in enumerate(input):
		if ord(character) < 48 or (ord(character) > 57 and ord(character) < 65) or (ord(character) > 90 and ord(character) < 96) or ord(character) > 122:
			if character != '@' and character != '.':
				return False
	return True

# print(checkEmail("normal@gmail.com")) # True
# print(checkUsername("Us3r12#%!@gmail.com"))