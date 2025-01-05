from algebra import mod_inv, mod_sqrt

### add (and double)

def add(x1:int, y1:int, x2:int, y2:int, p: int):
    a = 486662
    if (x1, y1) == (1, 0):
        return x2, y2
    if (x2, y2) == (1, 0):
        return x1, y1
    if x1 == x2 and y1 != y2:
        return (1, 0)
    if x1 == x2 and y1 == y2:
        m = ((3 * x1**2 + 2*a*x1 + 1)%p) * mod_inv(2 * y1, p)
        x3 = (m**2 - a - 2*x1)%p
    else:
        m = ((y2 - y1)%p) * mod_inv((x2 - x1)%p, p)
        x3 = (m**2 - a - x1 - x2)%p
    
    y3 = (m*(x1 - x3) - y1)%p
    return (x3, y3)

### substract

def sub(x1:int, y1:int, x2:int, y2:int, p: int):
    return add(x1, y1, x2, -y2, p)

### unoptimized and not constant-time scalar multiplication

def mult(n, x1, y1, p):
    tx, ty = 1, 0
    for bit in map(int, bin(n)[2:]):
        tx, ty = add(tx, ty, tx, ty, p)
        if bit:
            tx, ty = add(tx, ty, x1, y1, p)
    return tx, ty


### encoding and decoding functions from RFC 7448

def decodeLittleEndian(b, bits):
    return sum([ b[i] << 8*i for i in range((bits+7)//8) ])

def decodeUCoordinate(u, bits):
    u_list = [b for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1 << (bits % 8)) - 1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits):
    return bytearray([ (u >> 8*i) & 0xff for i in range((bits+7)//8) ])

def decodeScalar25519(k):
    k_list = [b for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

### optimized and constant time scalar multiplication from RFC 7448

def cswap(swap, x_2, x_3):
    x_ = swap * (x_2 - x_3)
    x_2 = x_2 - x_
    x_3 = x_3 + x_
    return x_2, x_3

def mul(k: int, u: int, bits: int, p: int, a24: int):
    
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1

    swap = 0

    for t in range(bits-1, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        (x_2, x_3) = cswap(swap, x_2, x_3)
        (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t

        A = (x_2 + z_2) % p
        AA = pow(A, 2, p)
        B = (x_2 - z_2) % p
        BB = pow(B, 2, p)
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x_3 = pow((DA + CB), 2, p)
        z_3 = (x_1 * (DA - CB)**2) % p
        x_2 = (AA * BB) % p
        z_2 = (E * (AA + a24 * E)) % p

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    res = x_2 * pow(z_2, p-2, p) % p
    return res

### computes decoding, scalar multiplication and encoding for the u-coordinate

def x25519(k: bytes, u: bytes):
    bits = 255
    k = decodeScalar25519(k)
    u = decodeUCoordinate(u, bits)
    p = 2**255 - 19
    a24 = 121665
    res = mul(k, u, bits, p, a24)
    return encodeUCoordinate(int(res), bits)

### computes v-coordinate from u-coordinate

def computeVcoordinate(u):
    VV = (pow(u, 3, 2**255 - 19)+486662*pow(u,2,2**255 - 19) + u)%(2**255 - 19)
    V = mod_sqrt(VV, 2**255 - 19)
    return V
