from werkzeug.security import generate_password_hash, check_password_hash

def hashPassword(password):
  return generate_password_hash(password, method='sha256')

def checkIfHashedPasswordIsCorrect(passwordInDataBase, password):
  return check_password_hash(passwordInDataBase, password)
