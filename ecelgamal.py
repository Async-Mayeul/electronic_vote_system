from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint

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

def ECEG_generate_keys(u,v,p,order):
    x = randint(1, order - 1)
    Y_x,Y_y = mult(x,u,v,p)

    return x, (Y_x,Y_y)
    
def ECEG_encrypt(Y_point,u,v,p,order,message):
    k = randint(1, order - 1)
    c1_x,c1_y = mult(k,u,v,p)
    c2_x,c2_y = mult(k,Y_point[0],Y_point[1],p)
    pm_u,pm_v = EGencode(message)
    d_x,d_y = add(c2_x,c2_y,pm_u,pm_v,p)

    return (c1_x,c1_y),(d_x,d_y)

def ECEG_decrypt(x,C_Point,D_Point,p):
    c_x,c_y = mult(x,C_Point[0],C_Point[1],p)
    pm_x,pm_y = sub(D_Point[0],D_Point[1],c_x,c_y,p)

    return pm_x,pm_y
