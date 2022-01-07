import gmpy2
import binascii
import math
from split_frame import n,e,c

# Frame10

def fermat(n, verbose=True):
    n = int(n,base=16)
    a0 = gmpy2.iroot(n,2)[0]+1 # int(ceil(n**0.5))
    count = 0
    b = 0
    while count<1000000:
        a = a0 + count
        v = a*a - n
        if gmpy2.is_square(v):
            b = gmpy2.isqrt(v)
            break
        count += 1
    if (b==0):
        print("error")
    p= a + b
    q= a - b
    return p, q


def frame10(n,c,e):
    p = fermat(n)[0]
    q = fermat(n)[1]
    s = (p-1)*(q-1)
    n = int(n,base=16)
    c = int(c, base=16)
    e = int(e,base=16)
    d = gmpy2.invert(e, s)
    m = pow(c, d, n)
    result = binascii.a2b_hex(hex(m)[-16:])
    return result


if __name__ == "__main__":
#    print(fermat(n[10]))
    print("Frame10: ", frame10(n[10],c[10],e[10]))
