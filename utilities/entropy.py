import numpy
from math import log2

def countascii(s):
  count = numpy.zeros(256)
  for c in s:
      count[ord(c)]+= 1
  return count


def calculateEntropy(password):
  count = countascii(password)
  chars = numpy.arange(0, 255+1)
  length = len(password)
  p = numpy.zeros(length)
  p = count / length
  H = 0.0
  for i in range(256):
      if p[i] > 0:
          H += -p[i]*log2(p[i])
  return H

def printHowStrongIsYourPassword(entropy):
  s = "Your password entropy= " + str(entropy) + " (max = 8), (min = 0)"
  if entropy <= 1:
    s += ". This is very weak password!"
  elif entropy <= 3:
    s += ". This is weak password!"
  elif entropy <= 4:
    s += ". This password is not so bad!"
  else:
    s += ". This password is very strong!"
  return s

# print(calculateEntropy("password")) # 2.75
# print(calculateEntropy("Tr0ub4dor&3")) # 3.28
# print(calculateEntropy("correcthorsebatterystaple")) # 3.37

# # Secure Password Generator - https://passwordsgenerator.net/:
# print(calculateEntropy("DrSK_B2/yw%P$KaU")) # 3.88
# print(calculateEntropy("XN_>qYwTnp9=WB+7")) # 4.0