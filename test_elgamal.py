from elgamal import *

def multiplicativeTest():
    m1 = 0x2661b673f687c5c3142f806d500d2ce57b1182c9b25bfe4fa09529424b
    m2 = 0x1c1c871caabca15828cf08ee3aa3199000b94ed15e743c3

    x,h = EG_generate_keys(PARAM_P,PARAM_G)
    r1,c1 = EGM_encrypt(PARAM_P,PARAM_G,h,m1)
    r2,c2 = EGM_encrypt(PARAM_P,PARAM_G,h,m2)

    (r3,c3) = (r1*r2,c1*c2)
    m3 = EG_decrypt(x,PARAM_P,r3,c3)

    print(f'Message 3 = {m3}')

def additiveTest():
    m1 = 1
    m2 = 0
    m3 = 1
    m4 = 1
    m5 = 0

    x,h = EG_generate_keys(PARAM_P,PARAM_G)

    r1,c1 = EGA_encrypt(PARAM_P,PARAM_G,h,m1)
    r2,c2 = EGA_encrypt(PARAM_P,PARAM_G,h,m2)
    r3,c3 = EGA_encrypt(PARAM_P,PARAM_G,h,m3)
    r4,c4 = EGA_encrypt(PARAM_P,PARAM_G,h,m4)
    r5,c5 = EGA_encrypt(PARAM_P,PARAM_G,h,m5)

    r,c = (r1*r2*r3*r4*r5,c1*c2*c3*c4*c5)

    gm = EG_decrypt(x,PARAM_P,r,c)
    m = bruteLog(PARAM_G,gm,PARAM_P)

    print(f'Votes = {m}')

if __name__ == "__main__":
    multiplicativeTest()
    additiveTest()
