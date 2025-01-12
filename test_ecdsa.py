from ecdsa import *

m = b'A very very important message !'
k = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
x = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8

r,s = ECDSA_sign(BaseU,BaseV,x,ORDER,p,k,m)

print(f'r = {r:064x}\ns = {s:064x}')

k,k_inv = ECDSA_generate_nonce(ORDER)
x,y = ECDSA_generate_keys(ORDER,BaseU,BaseV,p)
r,s = ECDSA_sign(BaseU,BaseV,x,ORDER,p,k,m)
isVerified = ECDSA_verify(r,s,y,BaseU,BaseV,ORDER,p,m)

if isVerified:
    print("Message verified !")
