from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint
#from algebra import bruteLog

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)

def bruteECLog(C1, C2, p):
    s1, s2 = 1, 0
    for i in range(p):
        print(str(i) + " : " + str(s1) + "," + str(s2))
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BaseU, BaseV, p)
    return -1

def EGencode(message):
    if message == 0:
        return (1,0)
    if message == 1:
        return (BaseU, BaseV)


"""
Generate EC ElGamal key pair.

Parameters:
    order (int): Order of the base point.
    base_point (tuple): The base point (BaseU, BaseV) on the elliptic curve.
    prime (int): The prime modulus of the finite field.

Returns:
    (private_key, public_key): 
        private_key: An integer (the secret scalar).
        public_key: A tuple (x, y) representing the public key point on the curve.
"""
def ECEG_generate_keys(order, base_point, prime):
    print("generating keys...\n")
    # Generate private key
    private_key = randint(1, order - 1)  # Random integer in range [1, order-1]

    # Generate public key
    public_key = mult(base_point[0], base_point[1], private_key, prime)  # Scalar multiplication

    print("key generation done\n")
    return private_key, public_key


"""
Encrypt a message using EC ElGamal.

Parameters:
    public_key (tuple): Recipient's public key as a point (x, y) on the curve.
    message_point (tuple): The message to encrypt, represented as a point (x, y) on the curve.
    base_point (tuple): The base point (BaseU, BaseV) on the elliptic curve.
    prime (int): The prime modulus of the finite field.
    order (int): The order of the base point.

Returns:
    (C1, C2): The ciphertext.
        C1 (tuple): The ephemeral public key (x, y) as a point on the curve.
        C2 (tuple): The encrypted message as a point on the curve.
"""
def ECEG_encrypt(public_key, message_point, base_point, prime, order):
    print("starting encryption...\n")
    # Generate ephemeral private key
    k = randint(1, order - 1)  # Random integer in range [1, order-1]

    # Compute ephemeral public key C1
    C1 = mult(base_point[0], base_point[1], k, prime)

    # Compute shared secret S = k * public_key
    S = mult(public_key[0], public_key[1], k, prime)

    # Encrypt the message: C2 = message_point + S
    C2 = add(message_point[0], message_point[1], S[0], S[1], prime)
    print("encryption done\n")
    return C1, C2


"""
Decrypt a message using EC ElGamal.

Parameters:
    private_key (int): Recipient's private key.
    ciphertext (tuple): The ciphertext (C1, C2) where:
        C1 (tuple): Ephemeral public key as a point (x, y) on the curve.
        C2 (tuple): Encrypted message as a point (x, y) on the curve.
    prime (int): The prime modulus of the finite field.

Returns:
    message_point (tuple): The decrypted message as a point (x, y) on the curve.
"""
def ECEG_decrypt(private_key, ciphertext, prime):
    print("starting decryption...\n")
    # Extract ciphertext components
    C1, C2 = ciphertext

    # Compute the shared secret S = private_key * C1
    S = mult(C1[0], C1[1], private_key, prime)

    # Decrypt the message: M = C2 - S
    message_point = sub(C2[0], C2[1], S[0], S[1], prime)

    print("decryption done\n")
    return message_point


# def ECEG_generate_keys():
#     return """TBC"""

# #TODO
# def ECEG_encrypt("""TBC"""):
#     return("""TBC""")

# #TODO
# def ECEG_decrypt("""TBC"""):
#     return("""TBC""")