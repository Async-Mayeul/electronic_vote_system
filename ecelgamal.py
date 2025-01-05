from rfc7448 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)

def ECEG_generate_keys("""TBC"""):
    return """TBC"""


def ECEG_encrypt("""TBC"""):
    return("""TBC""")


def ECEG_decrypt("""TBC"""):
    return("""TBC""")