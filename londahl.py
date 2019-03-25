import gmpy2

def close_factor(n, b):
 
    # approximate phi
    phi_approx = n - 2 * gmpy2.isqrt(n) + 1
 
    # create a look-up table
    look_up = {}
    z = 1
    for i in range(0, b + 1):
        look_up[z] = i
        z = (z * 2) % n
 
    # check the table
    mu = gmpy2.invert(pow(2, phi_approx, n), n)
    fac = pow(2, b, n)

    for i in range(0, b + 1):
        if mu in look_up:
            phi = phi_approx + (look_up[mu] - i * b)
            break
        mu = (mu * fac) % n
    else:
        return None
 
    m = n - phi + 1
    roots = (m - gmpy2.isqrt(m ** 2 - 4 * n)) // 2, \
            (m + gmpy2.isqrt(m ** 2 - 4 * n)) // 2
 
    assert roots[0] * roots[1] == n
    return roots
