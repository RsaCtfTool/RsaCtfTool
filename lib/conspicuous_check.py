import gmpy2
import math


def privatekey_check(N, p, q, d, e):
    ret = False
    txt = ""

    def getbits(n):
        b = int(math.log(n, 2))
        if b % 2 == 0:
            return b
        else:
            return b + 1

    nlen = getbits(N)
    if gmpy2.is_prime(p) == False:
        ret = True
        txt += "p IS NOT PROBABLE PRIME\n"
    if gmpy2.is_prime(q) == False:
        txt = "q IS NOT PROBABLE PRIME\n"
    if gmpy2.gcd(p, e) > 1:
        ret = True
        txt = "p and e ARE NOT RELATIVELY PRIME\n"
    if gmpy2.gcd(q, e) > 1:
        ret = True
        txt += "q and e ARE NOT RELATIVELY PRIME\n"
    if p * q != N:
        ret = True
        txt += "n IS NOT p * q\n"
    if not (abs(p - q) > (2 ** (nlen // 2 - 100))):
        ret = True
        txt += "|p - q| IS NOT > 2^(nlen/2 - 100)\n"
    if not (p > 2 ** (nlen // 2 - 1)):
        ret = True
        txt += "p IS NOT > 2^(nlen/2 - 1)\n"
    if not (q > 2 ** (nlen // 2 - 1)):
        ret = True
        txt += "q IS NOT > 2^(nlen/2 - 1)\n"
    if not (d > 2 ** (nlen // 2)):
        ret = True
        txt += "d IS NOT > 2^(nlen/2)\n"
    if not (d < gmpy2.lcm(p - 1, q - 1)):
        ret = True
        txt += "d IS NOT < lcm(p-1,q-1)\n"
    unc = (gmpy2.gcd(e - 1, p - 1) + 1) * (gmpy2.gcd(e - 1, q - 1) + 1)
    if unc > 9:
        ret = True
        txt += "The number of unconcealed messages is %d > min\n" % unc
    try:
        inv = gmpy2.invert(e, gmpy2.lcm(p - 1, q - 1))
    except:
        inv = None
        ret = True
        txt += "e IS NOT INVERTIBLE mod lcm(p-1,q-1)\n"
    if d != inv:
        ret = True
        txt += "d IS NOT e^(-1) mod lcm(p-1,q-1)"
    return (ret, txt)
