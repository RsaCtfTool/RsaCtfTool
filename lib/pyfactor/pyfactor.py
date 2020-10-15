from methods import \
    lu_table, p_rho, lenstra_ECM, q_sieve, gnfs
    
def factor(N):
    """ 
    factor() Determines which factor algorithm to use based on 
    the bitlength of N. The following 5 algorithms are used at 
    different bit length of N, denoted k. 

    k <= 16: lookup_table(N)
    16 < k <= 70: pollard_rho(N)
    70 < k <= 167: lenstra_elliptic_curve_method(N)
    167 < k <= 333: quadratic_sieve(N)   
    k > 333:  general_number_field_sieve(N)

    """

    if N < 0:
        return factor(-N) + [-1]
    elif is_probable_prime(N):
        return [N]
    else:
        k = N.bit_length()
        if k <= 16:
            return lookup_table(N)
        elif 16 < k <= 70:
            return pollard_rho(N)
        elif 70 < k <= 167:
            return lenstra_elliptic_curve_method(N)
        elif 167 < k <= 333:
            return quadratic_sieve(N)   
        else: 
            return general_number_field_sieve(N)
    
def lookup_table(N):
    """ Look-up-table method"""
    return lu_table(N)

def pollard_rho(N):
    """ Rollard_rho method"""
    return p_rho(N)

def lenstra_elliptic_curve_method(N):
    """ Hendrik Lenstra's ECM. Written completely in Cython """
    return lenstra_ECM(N)

def quadratic_sieve(N):
    """ Quadratic Sieve """
    return q_sieve(N)

def general_number_field_sieve(N):
    """ Factors N into list of primes with repitition """
    return gnfs(N)




