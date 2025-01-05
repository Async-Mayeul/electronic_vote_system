import math

def int_to_bytes(n):
    """Converts int to bytes."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def mod_inv(a, n):
    t, r = 1, a
    new_t, new_r = 0, n

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n
    return t
