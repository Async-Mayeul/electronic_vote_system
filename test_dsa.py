from dsa import *

m = b'An important message !'
k = 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759
x = 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3
r,s,status = DSA_sign(PARAM_P,PARAM_Q,PARAM_G,x,k,m)

print(f'r = {r:064x}\ns = {s:064x}')

k,k_inv = DSA_generate_nonce(PARAM_Q)
x,y,status = DSA_generate_keys(PARAM_P,PARAM_Q,PARAM_G)
r,s,status = DSA_sign(PARAM_P,PARAM_Q,PARAM_G,x,k,m)
isVerified = DSA_verify(r,s,PARAM_P,PARAM_Q,PARAM_G,y,m)

if isVerified:
    print("Message verified !")
