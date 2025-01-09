from algebra import mod_inv
from Crypto.Hash import SHA256
from random import randint

## parameters from MODP Group 24 -- Extracted from RFC 5114
FAILURE = False

SUCCESS = True

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

'''
Function to generate nonce or k in NIST fips 186.
This nonce need to be unique to each message.
Name: DSA_generate_nonce
Params:
    - int q: prime factor of p - 1
Return:
    - int k: per-message secret number
    - int k^-1: modular inverse of k
'''
def DSA_generate_nonce(q):
    k = 0
    k_inverse = 0

    while True:
        c = randint(1, int(q))
        if c <= ( int(q) - 2 ):
            k = c + 1
            k_inverse = mod_inv(k,int(q))
            return (k, k_inverse)

'''
Function to generate keys pair for DSA signature.
Name: DSA_generate_keys
Params:
    - int p: prime number that define GF(p)
    - int q: prime factor of p - 1
    - int g: generator of the q-order cyclic group of GF(p)*
Return:
    - int x: DSA private key
    - int y: DSA public key
    - int SUCCESS
'''
def DSA_generate_keys(p,q,g):
    x = 0
    y = 0

    while True:
        c = randint(1, int(q))
        if c <= ( int(q) - 2 ):
            x = c + 1
            y = pow(g, x, p)
            return (x, y, SUCCESS)

'''
Function used by the signatory to sign the message.
Name: DSA_sign
Params:
    - int p: prime number that define GF(p)
    - int q: prime factor of p - 1
    - int g: generator of the q-order cyclic group of GF(p)*
    - int x: DSA private key
    - int k: per message nonce
    - bytes message: sequence of bytes that correspond to the message
Return:
    if SUCCESS:
        - int r: a component of a DSA digital signature
        - int s: a component of a DSA digialt signature
    if FAILURE:
        - int FAILURE
'''
def DSA_sign(p,q,g,x,k,message):
    r = 0
    z = 0
    s = 0
    
    k_inverse = mod_inv(k,int(q))
    r = pow(g, k, p) % q

    if r != 0 :
        z = H(message)
        s = (k_inverse * (z + x*r)) % q
        if s != 0:
            return (r, s, SUCCESS)
        else:
            return FAILURE
    else:
        return FAILURE

'''
Function used by the receiver of the signature and the message 
to verify the integrity of the message.
Name: DSA_verify
Params:
    - int r: a component of a DSA digital signature
    - int s: a component of a DSA digital signature
    - int p: prime number that define GF(p)
    - int q: prime factor of p - 1
    - int g: generator of the q-order cyclic group of GF(p)*
    - int y: DSA public key
    - bytes message: sequence of bytes that correspond to the message
Return:
    SUCCESS if verification process validate the message
    otherwise FAILURE.
'''
def DSA_verify(r,s,p,q,g,y,message):
    w = 0
    z = 0
    v = 0
    u1 = 0
    u2 = 0

    if (0 < r < q) and (0 < s < q):
        w = mod_inv(s,int(q))
        z = H(message)
        u1 = (z * w) % q
        u2 = (r * w) % q
        v = ((pow(g,u1) * pow(y,u2)) % p) % q

        if v == r:
            return SUCCESS
        else:
            return FAILURE
    else:
        return FAILURE
