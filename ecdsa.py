from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv

FAILURE = False
SUCCESS = True
p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

'''
Function used to generate a nonce or k.
This nonce need to be unique for each message.
Name: ECDSA_generate_nonce
Params:
    - int n: order of G
Return:
    - int k: per-message secret number
    - int k_inverse: modular inverse of k
'''
def ECDSA_generate_nonce(n):
    k = 0
    k_inverse = 0

    while True:
        c = randint(1,int(n))
        if c <= int(n) - 2:
            k = c + 1
            k_inverse = mod_inv(k,n)
            return (k,k_inverse)

'''
Function to generate keys pair used by ECDSA.
Name: ECDSA_generate_keys
Params:
    - int n: order of G
    - int x: x coordinate of G
    - int y: y coordinate of G
    - int p: p elements of the finite field F_p
Return:
    - int d: private key
    - tuples Q_point: coordinates of the elliptic curve public key
'''
def ECDSA_generate_keys(n,x,y,p):
    d = 0
    Q_point = 0

    while True:
        c = randint(1,n)
        if c <= int(n) - 2:
            d = c + 1
            Q_point = mult(d,x,y,p)
            if Q_point != (1, 0):
                return (d,Q_point)

'''
Function used to sign a message with ECDSA.
Name: ECDSA_sign
Params:
    - int x: x coordinate of G
    - int y: y coordinate of G
    - int d: private key
    - int n: order of G
    - int p: p elements of the finite field F_p
    - int k: per-message secret
    - bytes message: sequence of bytes that correspond to the message
Return:
    - int r: a component of the signature
    - int s: a component of the signature
'''
def ECDSA_sign(x,y,d,n,p,k,message):
    e = H(message)

    while True:
        k_inverse = mod_inv(k,n)
        (i,j) = mult(k,x,y,p)
        r = i % n
        if r != 0:
            s = (k_inverse * (e + d*r)) % n
            if s != 0:
                return (r,s)

'''
Function used to verify a signature made with ECDSA.
Name: ECDSA_verify
Params:
    - int r: a component of the signature
    - int s: a component of the signature
    - Q_point: coordinates of the elliptic curve public key
    - int x: x coordinate of G
    - int y: y coordinate of G
    - int n: order of G
    - int p: p elements of the finite field F_p
    - bytes message: sequence of bytes that correspond to the message
Return:
    SUCCESS if the verification process validate the message otherwise
    FAILURE.
'''
def ECDSA_verify(r,s,Q_point,x,y,n,p,message):
    e = H(message)

    if (1 <= r <= n - 1) and (1 <= s <= n - 1):
        c = mod_inv(s,n)
        u_1 = (e*c) % n
        u_2 = (r*c) % n
        x1,y1 = mult(u_1,x,y,p)
        x2,y2 = mult(u_2,Q_point[0], Q_point[1],p)
        (i,j) = add(x1,y1,x2,y2,p)
        v = i % n
    else:
        return FAILURE
    
    if v == r:
        return SUCCESS
    else:
        return FAILURE
