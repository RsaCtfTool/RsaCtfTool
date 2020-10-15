import numpy as np
import sympy as sp
from factor import base_coeffs, primes_less_than, is_probable_prime, \
    randrange, gcd, mod_inv, legendre, primes_between, lazy_factors
from libc.math cimport fabs, floor, sqrt, log


cdef list lu_table(int n):
    pass

cdef list p_rho(int n):
    pass

cdef list lenstra_ECM(int n):
    if n < 0:
        return [-1] + lenstra_ECM(-n)
    if 0 <= n <= 3 or is_probable_prime(n):
        return [n]
    # create all the local variables as c ints
    cdef int x0, y0, b, d, s, x, y
    cdef double bound
    x0, y0 = randrange(1, n), randrange(1, n)
    bound = floor(sqrt(n))
    # Start trials looking for values where gcd(n,x-x0) !=1
    for a in xrange(1, n):
        # build elliptic curve using random points
        b = y0**2 - x0**3 - a * x0
        # Check if the curve is singular
        if 4 * a**3 - 27 * b**2 == 0:
            next
        d = gcd(2 * y0, n)
        if d != 1:
            return lenstra_ECM(d) + lenstra_ECM(n / d)
        # Initial double of the point (x0,y0)
        s = (3 * x0**2 + a) * mod_inv(2 * y0, n)
        x, y = (s**2 - 2 * x0, s * (3 * x0 - s**2) - y0)
        # Search for non-trivial gcd's
        for k in xrange(1, bound):
            for i in xrange(1, k):
                d = gcd(x - x0, n)
                if d != 1:
                    return lenstra_ECM(d) + lenstra_ECM(n / d)
                else:
                    s = (y - y0) * mod_inv(x - x0, n)
                    y = (s * (2 * x + x0 - s**2) - y) % n
                    x = (s**2 - x - x0) % n


cdef list q_sieve(int n):
    pass

cdef list gnfs(int n):
    # Can't factor a prime number!
    if is_probable_prime(n):
        return [n]
    # Determine the degree of the polynomial to be used
    # based on the bitlength of n
    k = log(n) * (1 / log(2))
    if k >= 110:
        d = 5.0
    elif 80 < k < 110:
        d = 4.0
    else:
        d = 3.0
    # Select a monic irreducible polynomial of degree d
    # with integer coefficients.
    c = 0
    while True:
        # Find the coefficients in the m base expansion of n
        # where m is the dth root of n, plus some constant c
        m = floor(n**(1 / d)) + c
        coefficients = base_coeffs(m, n)

        # Create polynomial f of degree d with coefficients
        # from 'coefficients'
        x = sp.symbols('x')
        f = sp.poly(x, domain=sp.ZZ) - x
        for i in xrange(0, len(coefficients)):
            f += coefficients[i] * x ** i

        # Test if f is irreducible over Q and that m is
        # still a root mod n
        if _irreducible(f) and f.eval(m) % n == 0:
            break
        else:
            c += 1

    # Create rational, algebraic and quadratic factor
    # bases for sieving
    rational, algebraic, quadratic = list(), list(), list()
    rational = primes_less_than(m)
    for p in primes_less_than(3 * m):
        for r in sp.ground_roots(f, modulus=p):
            algebraic.append((r, p))
    for p in xrange(3 * m, 4 * m):
        if is_probable_prime(p):
            for r in sp.ground_roots(f, modulus=p):
                quadratic.append((r, p))

    # Create a numpy matrix to store "smooth" elements
    factor_base_length = len(rational) + len(algebraic) + len(quadratic)
    U = np.zeros(shape=(factor_base_length + 2, factor_base_length + 1))

    # When number_of_smooths > factor_base_length we
    # stop sieving for "smooth" elements
    number_of_smooths = 0
    sample_size = 10000

    # Sieve for smooth pairs (a,b)
    b = 0
    while number_of_smooths < factor_base_length + 1:
        # b = rn.randrange(1, m)
        b += 1
        S = xrange(0, sample_size)
        R = [[] for _ in S]
        A = [[] for _ in S]
        # find smooth integers in Z and Z[theta]
        for i in xrange(1, len(S)):
            a = S[i]
            # a and b must be coprime
            if gcd(a, b) != 1:
                next
            # Two flags to keep track of whether (a,b) is smoooth in
            # Z and in Z[theta]
            is_rational_smooth = False
            is_algebraic_smooth = False
            # Build list of primes dividing a + b*m
            for p in rational:
                if (a + b * m) % p == 0:
                    l = 1
                    while (a + b * m) % (p**(l + 1)) == 0:
                        l += 1
                    R[i].append((p, l))

            # Build list of prime ideals "dividing" a + b*theta
            for (r, p) in algebraic:
                if (a + b * r) % p == 0:
                    l = 1
                    # while (a + b*r) % (p**(l+1)) == 0:
                    #     l+=1
                    A[i].append(((r, p), l))
            # Check if a + b*m is smooth over the rational factor base
            # and if a + b*theta is "smooth" over the algebraic factor base
            prod = 1
            for (p, l) in R[i]:
                prod *= p**l
            if a + b * m == prod:
                is_rational_smooth = True

            prod = 1
            for ((r, p), l) in A[i]:
                while l > 0:
                    prod *= p
                    l -= 1
            if prod == (-1)**(sp.degree(f)) * f.eval(-a / b):
                is_algebraic_smooth = True
            # If a+b*m and a+b*theta are smooth over the
            # rational and algebraic factor bases respectively
            # then add then add the exponents of their factorizations
            # to as a row in U.
            if is_rational_smooth and is_algebraic_smooth:
                # Exponents for rational factor base mod 2
                for j in xrange(0, len(rational)):
                    p = rational[j]
                    l = 0
                    while (a + b * m) % (p**(l + 1)) == 0:
                        l += 1
                    U[number_of_smooths, j] = l % 2
                # Expoenents of algebraic facctor base mod 2
                for j in xrange(0, len(algebraic)):
                    (r, p) = algebraic[j]
                    l = 0
                    if (a + b * r) % p == 0:
                        l = 1
                        # while (a+b*r) %(p**(l+1)) == 0:
                        #     l+=1
                    U[number_of_smooths, len(rational) + j] = l % 2
                # Quadratic residues
                for j in xrange(0, len(quadratic)):
                    (s, q) = quadratic[j]
                    if legendre(a + b * s, q) == 1:
                        U[number_of_smooths, len(
                            rational) + len(algebraic)] = 0
                    else:
                        U[number_of_smooths, len(
                            rational) + len(algebraic)] = 1
                number_of_smooths += 1
    return U


cdef list _prime_ideals(f, int lower, int upper):
    prime_ideals = []
    if lower == 0:
        for p in primes_between(lower, upper):
            for r in sp.ground_roots(f, modulus=p):
                prime_ideals.append((r, p))


cdef int _irreducible(f) except? -2:
    if f.eval(0) == 0:
        return False
    leading = [1, -1] + lazy_factors(f.coeffs()[0]) \
        + [-x for x in lazy_factors(f.coeffs()[0])]
    constant = lazy_factors(f.coeffs()[len(f.coeffs()) - 1]) \
        + [-x for x in lazy_factors(f.coeffs()[len(f.coeffs()) - 1])]
    for q in leading:
        for p in constant:
            if f.eval(p / q) == 0:
                return False
    return True


cdef double _norm(f, theta, alpha) except? -2:
    roots = sp.solve(f)
    norm = 1
    for theta_i in roots:
        norm *= alpha.subs(theta, theta_i)
    return norm.simplify()
