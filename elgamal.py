from algebra import mod_inv, int_to_bytes
from random import randint

PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3

PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

### call bruteLog with p = PARAM_P and g = PARAM_G
def bruteLog(g, c, p):
    s = 1
    for i in range(p):
        if s == c:
            return i
        s = (s * g) % p
        if s == c:
            return i + 1
    return -1

'''
Function to generate keys pair.
Name: EG_generate_keys
Params:
    - int p: prime number that define GF(p)
    - int g: generator of the cyclic group GF(p)*
Return:
    - int x: private key
    - int h: part of the public key {GF,p,q,h}
'''
def EG_generate_keys(p,g):
    x = randint(1,p-1)
    h = pow(g,x,p)

    return (x,h)

'''
Function that encrypt a message with the multiplicative
version of the El Gamal public key encryption.
Name: EGM_encrypt
Params:
    - int p: prime number that define GF(p)
    - int g: generator of the cyclic group GF(p)*
    - int h: part of the public key {GF,p,q,h}
    - bytes message: sequence of bytes that correspond to the message
Return:
    - int c1: part of the cyphertext
    - int c2: part of the cyphertext
''' 
def EGM_encrypt(p,g,h,message):
    k = randint(0,p-1)
    c1 = pow(g,k,p)
    c2 = (message * pow(h,k,p)) % p
    
    return (c1,c2)

'''
Function that encrypt a message with the additive
version of the El Gamal public key encryption.
Name: EGA_encrypt
Params:
    - int p: prime number that define GF(p)
    - int g: generator of the cyclic group GF(p)*
    - int h: part of the public key {GF,p,q,h}
    - bytes message: sequence of bytes that correspond to the message
Return:
    - int c1: part of the cyphertext
    - int c2: part of the cyphertext
'''
def EGA_encrypt(p,g,h,message):
    k = randint(0,p-1)
    c1 = pow(g,k,p)
    c2 = (pow(g,message,p) * pow(h,k,p)) % p
    
    return (c1,c2)

'''
Function that decrypt a message encrypted with
the El Gamal public key encryption.
Name: EG_decrypt
Params:
    - int x: private key
    - int p: prime number that define GF(p)
    - int c1: part of the cyphertext
    - int c2: part of the cyphertext
Return:
    - bytes message: sequence of bytes that correspond to the
    decrypted message
'''
def EG_decrypt(x,p,c1,c2):
    s = pow(c1,x,p)
    s_inv = mod_inv(s,p)
    message = (c2 * s_inv) % p

    return message
