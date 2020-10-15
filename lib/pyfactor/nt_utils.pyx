from libc.math cimport fabs, floor, sqrt
from libc.stdlib cimport rand

# These number theoretic functions should only rely on
# the C standard library and python built in functions.
# Any higher level functions should be in the methods module.


cdef int order_p(int N, int p) except? -2:
    cdef int e
    if N % p != 0:
        return 0
    else:
        e = 1
        while N % p**(e + 1) == 0:
            e += 1
        return e


cdef list base_coeffs(int b, int N):
    coeffs = []
    while N != 0:
        coeffs.append(N % b)
        N /= b
    return coeffs


cdef list primes_less_than(int N):
    sieve = [True] * N
    for i in xrange(3, int(N ** 0.5) + 1, 2):
        if sieve[i]:
            sieve[i * i::2 * i] = [False] * ((N - i * i - 1) / (2 * i) + 1)
    return [2] + [i for i in xrange(3, N, 2) if sieve[i]]


cdef list primes_between(int lower, int upper):
    cdef double n
    if upper - lower < 0:
        raise Exception("Cannot find primes in negative range")
    else:
        primes = []
        sieve = [False] * upper
        for i in xrange(1, floor(sqrt(upper)) + 1):
            for j in xrange(1, floor(sqrt(upper)) + 1):
                n = 4 * i**2 + j**2
                if n <= upper and (n % 12 == 1 or n % 12 == 5):
                    sieve[n] = not sieve[n]
                n = 3 * i**2 + j**2
                if n <= upper and n % 12 == 7:
                    sieve[n] = not sieve[n]
                n = 3 * i**2 - j**2
                if i > j and n <= upper and n % 12 == 11:
                    sieve[n] = not sieve[n]
        for i in xrange(5, floor(sqrt(upper))):
            if sieve[i]:
                for j in range(i**2, upper + 1, i**2):
                    sieve[j] = False
        for i in xrange(lower, upper):
            if sieve[i]:
                primes.append(i)
        return primes


cdef int try_composite(int a, int s, int N, int d) except? -2:
    if a ** d % N == 1:
        return 0
    for i in range(s):
        if a ** (2 ** i * d) % N == N - 1:
            return 0
    return 1


cdef int is_probable_prime(int N) except? -2:
    if N == 2:
        return 1
    if N % 2 == 0:
        return 0
    cdef s, d, quotient, remainder
    s = 0
    d = N - 1
    while 1:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert(2 ** s * d == N - 1)
    cdef number_of_trials = 12
    cdef int a = 1
    for i in range(number_of_trials):
        while a >= 2:
            a = randrange(2, N)
        if try_composite(a, s, N, d):
            return 0
    return 1


cdef int randrange(int l, int u) except? -2:
    if l > u:
        raise Exception("Cannot pick integer from negative range")
    return (rand() % (u - l + 1)) + l


cdef int extended_gcd(int a, int b) except? -2:
    if a < 0:
        a = -a
    if b < 0:
        b = -b
    cdef int x, lastx, y, lasty, quotient
    x, lastx, y, lasty = 0, 1, 1, 0
    while b:
        a, (quotient, b) = b, divmod(a, b)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return a, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)


cdef int gcd(int a, int b) except? -2:
    while b:
        a, b = b, a % b
    if a >= 0:
        return a
    else:
        return -a


cdef int mod_inv(int a, int m) except? -2:
    cdef int g, x, y
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

# Temporary fix
def lenstra_ECM(N):
    pass


cdef int legendre(int a, int p) except? -2:
    if not is_probable_prime(p) or p <= 2:
        raise Exception("p must be prime")
    cdef int s = 1
    for x in lenstra_ECM(a):
        s *= f(x, p)
    return s


cdef int f(int q, int p) except? -2:
    if q == 1:
        return 1
    elif q % p == 0:
        return 0
    elif q == -1:
        if p % 4 == 1:
            return 1
        else:
            return -1
    elif q == 2:
        if p % 8 == 1 or p % 8 == 7:
            return 1
        if p % 8 == 3 or p % 8 == 5:
            return -1
    elif q > p:
        return f(q % p, p)
    elif q % 4 == 1 or p % 4 == 1:
        return f(p, q)
    else:
        return -f(p, q)
