from ecelgamal import *
x,y = ECEG_generate_keys(BaseU,BaseV,p,ORDER)
messages = [1,0,1,1,0]
enc = [ECEG_encrypt(y,BaseU,BaseV,p,ORDER,m) for m in messages]

r,c = (1,0), (1,0)

for c1,c2 in enc:
    r = add(r[0],r[1],c1[0],c1[1],p)
    c = add(c[0],c[1],c2[0],c2[1],p)

pm = ECEG_decrypt(x,r,c,p)
m = bruteECLog(pm[0],pm[1],p)
print(f'Message {m}')
