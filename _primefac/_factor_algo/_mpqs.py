from __future__ import division

# Multiple Polynomial Quadratic Sieve
# Most of this function is copied verbatim from
# https://codegolf.stackexchange.com/questions/8629/9088#9088
def mpqs(n):
    """
    When the bound proves insufficiently large, we throw out all our work and
    start over.
    TODO: When this happens, get more data, but don't trash what we already
          have.
    TODO: Rewrite to get a few more relations before proceeding to the
          linear algebra.
    TODO: When we need to increase the bound, what is the optimal increment?
    """
    from _primefac._arith import ispower, isqrt, ilog, gcd, mod_sqrt, legendre
    from _primefac._arith import modinv
    from _primefac._prime import isprime, nextprime
    from _primefac._util import listprod, mpz
    from six.moves import xrange
    from math import log

    # Special cases: this function poorly handles primes and perfect powers:
    m = ispower(n)
    if m:
        return m
    if isprime(n):
        return n

    root_2n = isqrt(2*n)
    bound = ilog(n**6, 10)**2  # formula chosen by experiment

    while True:
        try:
            prime, mod_root, log_p, num_prime = [], [], [], 0

            # find a number of small primes for which n is a quadratic residue
            p = 2
            while p < bound or num_prime < 3:
                leg = legendre(n % p, p)
                if leg == 1:
                    prime += [p]
                    # the rhs was [int(mod_sqrt(n, p))].
                    # If we get errors, put it back.
                    mod_root += [mod_sqrt(n, p)]
                    log_p += [log(p, 10)]
                    num_prime += 1
                elif leg == 0:
                    return p
                p = nextprime(p)

            x_max = len(prime)*60 # size of the sieve

            # maximum value on the sieved range
            m_val = (x_max * root_2n) >> 1

            """
            fudging the threshold down a bit makes it easier to find powers of
            primes as factors as well as partial-partial relationships, but it
            also makes the smoothness check slower. there's a happy medium
            somewhere, depending on how efficient the smoothness check is
            """
            thresh = log(m_val, 10) * 0.735

            # skip small primes. they contribute very little to the log sum
            # and add a lot of unnecessary entries to the table instead, fudge
            # the threshold down a bit, assuming ~1/4 of them pass
            min_prime = mpz(thresh * 3)
            fudge = sum(log_p[i] for i, p in enumerate(prime) if p < min_prime)
            fudge = fudge // 4
            thresh -= fudge

            smooth, used_prime, partial = [], set(), {}
            num_smooth, num_used_prime, num_partial = 0, 0, 0
            num_poly, root_A = 0, isqrt(root_2n // x_max)

            while num_smooth <= num_used_prime:
                # find an integer value A such that:
                # A is =~ sqrt(2*n) // x_max
                # A is a perfect square
                # sqrt(A) is prime, and n is a quadratic residue mod sqrt(A)
                while True:
                    root_A = nextprime(root_A)
                    leg = legendre(n, root_A)
                    if leg == 1:
                        break
                    elif leg == 0:
                        return root_A
                A = root_A**2
                # solve for an adequate B. B*B is a quadratic residue mod n,
                # such that B*B-A*C = n. this is unsolvable if n is not a
                # quadratic residue mod sqrt(A)
                b = mod_sqrt(n, root_A)
                B = (b + (n - b*b) * modinv(b + b, root_A)) % A
                C = (B*B - n) // A        # B*B-A*C = n <=> C = (B*B-n)//A
                num_poly += 1
                # sieve for prime factors
                sums, i = [0.0]*(2*x_max), 0
                for p in prime:
                    if p < min_prime:
                        i += 1
                        continue
                    logp = log_p[i]
                    g = gcd(A, p)
                    if g == p:
                      continue
                    inv_A = modinv(A // g, p // g) * g
                    # modular root of the quadratic
                    a, b, k = (mpz(((mod_root[i] - B) * inv_A) % p),
                               mpz(((p - mod_root[i] - B) * inv_A) % p),
                               0)
                    while k < x_max:
                        if k+a < x_max:
                            sums[k+a] += logp
                        if k+b < x_max:
                            sums[k+b] += logp
                        if k:
                            sums[k-a+x_max] += logp
                            sums[k-b+x_max] += logp
                        k += p
                    i += 1
                # check for smooths
                i = 0
                for v in sums:
                    if v > thresh:
                        x, vec, sqr = x_max-i if i > x_max else i, set(), []
                        # because B*B-n = A*C
                        # (A*x+B)^2 - n = A*A*x*x+2*A*B*x + B*B - n
                        #               = A*(A*x*x+2*B*x+C)
                        # gives the congruency
                        # (A*x+B)^2 = A*(A*x*x+2*B*x+C) (mod n)
                        # because A is chosen to be square, it doesn't
                        # need to be sieved
                        sieve_val = (A*x + 2*B)*x + C
                        if sieve_val < 0:
                            vec, sieve_val = {-1}, -sieve_val
                        for p in prime:
                            while sieve_val % p == 0:
                                if p in vec:
                                    """
                                    track perfect sqr facs to avoid sqrting
                                    something huge at the end
                                    """
                                    sqr += [p]  
                                vec ^= {p}
                                sieve_val = mpz(sieve_val // p)
                        if sieve_val == 1:  # smooth
                            smooth += [(vec, (sqr, (A*x+B), root_A))]
                            used_prime |= vec
                        elif sieve_val in partial:
                            """
                            combine two partials to make a (xor) smooth that
                            is, every prime factor with an odd power is in our
                            factor base
                            """
                            pair_vec, pair_vals = partial[sieve_val]
                            sqr += list(vec & pair_vec) + [sieve_val]
                            vec ^= pair_vec
                            smooth += [(vec, (sqr + pair_vals[0],
                              (A*x+B)*pair_vals[1], root_A*pair_vals[2]))]
                            used_prime |= vec
                            num_partial += 1
                        else:
                            # save partial for later pairing
                            partial[sieve_val] = (vec, (sqr, A*x+B, root_A))
                    i += 1
                num_smooth, num_used_prime = len(smooth), len(used_prime)
            used_prime = sorted(list(used_prime))
            # set up bit fields for gaussian elimination
            masks, mask, bitfields = [], 1, [0]*num_used_prime
            for vec, _ in smooth:
                masks += [mask]
                i = 0
                for p in used_prime:
                    if p in vec:
                        bitfields[i] |= mask
                    i += 1
                mask <<= 1
            # row echelon form
            offset = 0
            null_cols = []
            for col in xrange(num_smooth):
                pivot = bitfields[col-offset] & masks[col] == 0  # This occasionally throws IndexErrors.
                # TODO: figure out why it throws errors and fix it.
                for row in xrange(col+1-offset, num_used_prime):
                    if bitfields[row] & masks[col]:
                        if pivot:
                            bitfields[col-offset], bitfields[row], pivot = bitfields[row], bitfields[col-offset], False
                        else:
                            bitfields[row] ^= bitfields[col-offset]
                if pivot:
                    null_cols += [col]
                    offset += 1
            # reduced row echelon form
            for row in xrange(num_used_prime):
                mask = bitfields[row] & -bitfields[row]        # lowest set bit
                for up_row in xrange(row):
                    if bitfields[up_row] & mask:
                        bitfields[up_row] ^= bitfields[row]
            # check for non-trivial congruencies
            # TODO: if none exist, check combinations of null space columns...
            # if _still_ none exist, sieve more values
            for col in null_cols:
                all_vec, (lh, rh, rA) = smooth[col]
                lhs = lh   # sieved values (left hand side)
                rhs = [rh]  # sieved values - n (right hand side)
                rAs = [rA]  # root_As (cofactor of lhs)
                i = 0
                for field in bitfields:
                    if field & masks[col]:
                        vec, (lh, rh, rA) = smooth[i]
                        lhs += list(all_vec & vec) + lh
                        all_vec ^= vec
                        rhs += [rh]
                        rAs += [rA]
                    i += 1
                factor = gcd(listprod(rAs)*listprod(lhs) - listprod(rhs), n)
                if 1 < factor < n:
                    return factor
        except IndexError:
            pass
        bound *= 1.2

__all__ = [mpqs]
