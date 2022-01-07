import binascii
import gmpy2
from split_frame import n,c,e
import math

# Frame2,Frame6,Frame19
def pollard(n):
    m = 2
    max = 2**20
    for i in range(2,max+1):
        m = pow(m,i,n)
        factor = gmpy2.gcd(m-1,n)
        if (factor>=2) and (factor<=n-1):
            t = n//factor
            n = t*factor
    return factor


def pollard_resolve(n,c,e):
    n = int(n, base=16)
    c = int(c, base=16)
    e = int(e, base=16)
    p = pollard(n)
    q = n // p
    s = (p-1)*(q-1)
    d = gmpy2.invert(e, s)
    m = gmpy2.powmod(c, d, n)
    result = binascii.a2b_hex(hex(m)[-16:])
    return result

if __name__ == "__main__":
#    print(pollard(n[2]))
    print("Frame2:  ", pollard_resolve(n[2],c[2],e[2]))
    print("Frame6:  ", pollard_resolve(n[6],c[6],e[6]))
    print("Frame19: ", pollard_resolve(n[19],c[19],e[19]))