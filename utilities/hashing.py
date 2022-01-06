from werkzeug.security import generate_password_hash, check_password_hash

# https://techmonger.github.io/4/secure-passwords-werkzeug/
# generate_password_hash by default produces salt string with length 8 (which means we hash(password + salt))

def hashPassword(password):
  return generate_password_hash(password, method='sha256')

def checkIfHashedPasswordIsCorrect(passwordInDataBase, password):
  return check_password_hash(passwordInDataBase, password)