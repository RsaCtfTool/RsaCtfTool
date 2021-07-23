# packages (optional):
# sage --pip install coloredlogs

import time
import argparse
import sys
import logging
import traceback

from sage.misc.prandom import randrange
from sage.parallel.decorate import fork


debug = False
logger = logging.getLogger(__name__)


try:
    import coloredlogs
    coloredlogs.CHROOT_FILES = []
    coloredlogs.install(level=logging.DEBUG, use_chroot=False)
except:
    pass


class AlgException(Exception):
    pass


class NotInvertibleException(AlgException):
    pass


class NotFactoredException(AlgException):
    pass


class FactorRes(object):
    def __init__(self, r=None, c=None, u=None, a=None, th=None, tq=None):
        self.r = r
        self.c = c
        self.u = u
        self.a = a
        self.time_hilbert = th
        self.time_q = tq
        self.time_a = None
        self.time_last_div = None
        self.time_last_gcd = None
        self.time_last_nrm = None
        self.time_total = 0
        self.time_agg_div = 0
        self.time_agg_gcd = 0
        self.time_agg_nrm = 0
        self.time_qinv_char_poly = 0
        self.time_qinv_xgcd = 0
        self.time_qinv_res = 0
        self.rand_elem = None
        self.fact_timeout = None
        self.out_of_time = False
        self.use_quinv2 = False
        self.use_cheng = False


def is_undef(result):
    return result in ['NO DATA (timed out)', 'NO DATA', 'INVALID DATA', 'INVALID DATA ', None]


def class_number(d):
    k = QuadraticField(-d, 'x')
    return k.class_number()


def random_cm_prime_sub(thresh_l, thresh_h, rstart, rstop, D):
    while True:
        s = -1

        # Better is sqrt distribution as with uniform on i we get skew on i^2
        while True:
            s = randrange(thresh_l, thresh_h)
            s = int(isqrt((4r * s - 1r) / D))  # memory leak: s = int(sqrt((4 * s - 1) / D))
            if s & 1r == 1r and s >= rstart and s <= rstop:
                break

        p = int((D * s * s + 1r) / 4r)
        if p > thresh_h or p < thresh_l:
            continue
        if is_prime(p):
            return p


def generateCMprime(D, bits, verb = 1):
    if D % 8 != 3:
        raise ValueError('D must be congruent to 3 modulo 8')

    p = None
    thresh_l = 1 << (bits - 1)
    thresh_h = (1 << bits) - 1

    # Exact bounds to cover the whole interval
    rstart = int(isqrt((4r*thresh_l-1r)/D))
    rstop  = int(isqrt((4r*thresh_h-1r)/D))+1r

    while True:
        p = random_cm_prime_sub(thresh_l, thresh_h, rstart, rstop, D)
        if p:
            return p


def xgcd(f, g, N=1):
    toswap = False
    if f.degree() < g.degree():
        toswap = True
        f, g = g, f
    r_i = f
    r_i_plus = g
    r_i_plus_plus = f

    s_i, s_i_plus = 1, 0
    t_i, t_i_plus = 0, 1

    while (True):
        lc = r_i.lc().lift()
        lc *= r_i_plus.lc().lift()
        lc *= r_i_plus_plus.lc().lift()
        divisor = gcd(lc, N)
        if divisor > 1:
            print('Divisisor of %s is %s'%(N,divisor))
            return divisor, None, None

        q = r_i // r_i_plus
        s_i_plus_plus = s_i - q * s_i_plus
        t_i_plus_plus = t_i - q * t_i_plus
        r_i_plus_plus = r_i - q * r_i_plus
        if r_i_plus.degree() <= r_i_plus_plus.degree() or r_i_plus_plus.degree() == -1:
            if toswap == True:
                assert (r_i_plus == s_i_plus * f + t_i_plus * g)
                return r_i_plus, t_i_plus, s_i_plus
            else:
                assert (r_i_plus == s_i_plus * f + t_i_plus * g)
                return r_i_plus, s_i_plus, t_i_plus,
        r_i, r_i_plus = r_i_plus, r_i_plus_plus
        s_i, s_i_plus = s_i_plus, s_i_plus_plus
        t_i, t_i_plus = t_i_plus, t_i_plus_plus
        check_res = r_i == s_i * f + t_i * g
        if not check_res:
            logger.error('Assertion error: %s, %s != %s * %s + %s * %s' % (check_res, r_i, s_i, f, t_i, g))
            raise ValueError('xgcd assertion error')


def Qinverse(Q, a, N):
    """
    Q is a quotient ring of Z_N[x], a is the element to be inverted
    :param Q:
    :param a:
    :return:
    """
    j = Q.gens()[0]
    deg =  j.charpoly('X').degree()
    A = Q(a).matrix()
    det_a = det(A)
    logger.debug('DetA: %s' % det_a)

    factor = gcd(int(det_a), N)
    if factor!=1:  # a is not invertible
        raise ZeroDivisionError(a)

    else:
        Y = vector([1] + (deg-1)*[0])
        X = A.solve_left(Y)
        jvec = vector([j^i for i in [0..deg-1]])
        Xj = jvec*X
        return Xj


def Qinverse2 (Hx, a, N, time_res):
    ts = time.time()
    r,s,t = xgcd(a.lift(), Hx, N)
    txgcd = time.time()
    if (s,t) == (None, None):
        res = r, 0
    else:
        rinv = r[0]^(-1)
        res = 1, s * rinv
    tres = time.time()

    time_res.time_qinv_char_poly = 0
    time_res.time_qinv_xgcd = txgcd - ts
    time_res.time_qinv_res = tres - txgcd
    return res


def CMfactor(D, N, verb = 1, ctries=10, utries=10, fact_time=None, use_quinv2=False, use_cheng=False):
    """
    Try to factor N with respect to D, with ctries values of c and utries values of u
    """
    ts = time.time()
    Hx = hilbert_class_polynomial(-D)
    tth = time.time()
    if verb == 1:
        logger.debug('Hilbert polynomial computed for -%s!' % D)

    res = FactorRes()
    res.use_quinv2 = use_quinv2
    res.use_cheng = use_cheng

    ZN = Integers(N)
    R.<x> = PolynomialRing(ZN)

    ttq = time.time()
    try:
        if use_quinv2:
            Hx = R(Hx)
            Q.<j> = QuotientRing(R, R.ideal(Hx))
            gcd, inverse = Qinverse2(Hx, 1728 - j, N, res)  
            if gcd == 1:
                a = Q(j * inverse)                

        else:
            Q.<j> = ZN.extension(Hx)
            a = j * Qinverse(Q, 1728 - j, N)

    except ZeroDivisionError as noninv:
        logger.warning("is not invertible in Q! %s" % noninv)
        raise NotInvertibleException()
    if gcd != 1:
        exit(-1)
    if verb == 1:
        logger.debug('Q constructed')
        logger.debug('a computed: %s' % a)

    tta = time.time()
    res.time_agg_div = 0
    res.time_agg_gcd = 0
    res.time_hilbert = tth - ts
    res.time_q = ttq - tth
    res.time_a = tta - ttq
    res.a = None

    core_fnc = CMfactor_core
    if fact_time:
        time_left = fact_time - (tta - ts)
        res.fact_timeout = time_left
        core_fnc = fork(CMfactor_core, time_left)
    cres = core_fnc(N, ctries, utries, a, Q, ZN, Hx, res, use_cheng=use_cheng)
    if is_undef(cres):
        res.out_of_time = True
    else:
        res = cres

    tdone = time.time()
    res.time_total = tdone - ts
    return res


def CMfactor_core(N, ctries, utries, a, Q, ZN, Hx, res, use_cheng=False):
    is_done = False

    # We prove this takes only one iteration
    for c in [1..ctries]:
        E = EllipticCurve(Q, [0, 0, 0, 3 * a * c ^ 2, 2 * a * c ^ 3])

        # expected number of u iterations: cn^2 / (cn^2 - 1)
        for u in [1..utries]:

            # Division polynomial is the most expensive part here
            tcs = time.time()
            rand_elem = ZN.random_element()
            res.rand_elem = int(rand_elem)

            w = E.division_polynomial(N, Q(rand_elem), two_torsion_multiplicity=0)
            ttdiv = time.time()
            logger.debug('Division polynomial done')

            if use_cheng:
                poly_gcd = xgcd(w.lift(), Hx, N)[0]
                ttnrm = time.time()
                r = gcd(ZZ(poly_gcd), N)
                ttgcd = time.time()

            else:
                nrm = w.norm()
                ttnrm = time.time()
                r = gcd(nrm, N)
                ttgcd = time.time()

            res.time_agg_div += ttdiv - tcs
            res.time_agg_gcd += ttgcd - ttdiv
            res.time_agg_nrm += ttnrm - ttdiv
            res.c = int(c)
            res.u = int(u)
            res.time_last_div = ttdiv - tcs
            res.time_last_gcd = ttgcd - ttdiv
            res.time_last_nrm = ttnrm - ttdiv

            if r > 1 and r != N:
                res.r = int(r)
                logger.debug('A factor of N: %s' % r)
                logger.debug('c: %s, u: %s' % (c, u))
                is_done = True
                break

            else:
                logger.info('u failed: %s, next_attempt' % u)

        if is_done:
            break

    return res


def work_generate(args):
    logger.debug('Generating CM prime with D=%s, bits=%s' % (args.disc, args.prime_bits))
    p = generateCMprime(args.disc, args.prime_bits)
    print(p)


def work_factor(args):
    disc = args.disc
    class_num = class_number(disc)
    sys.setrecursionlimit(50000)  # for the computation of division polynomials

    success = False
    ts = time.time()
    logger.debug('D: %s, class_num: %s' % (disc, class_num))

    try:
        factor_timeout = args.timeout if args.timeout > 0 else None
        res = CMfactor(disc, args.mod, 1, fact_time=factor_timeout, use_quinv2=args.qinv2, use_cheng=args.cheng)
        res = -1 if is_undef(res) else res
        result = res if res and not isinstance(res, int) else None

        time_total = time.time() - ts
        logger.debug('Total time elapsed: %s' % time_total)

        if result.r > 1:
            if args.mod % result.r != 0:
                raise ValueError('Found result is invalid')

            q = args.mod // result.r
            success = True
            print("Factorization of N: %s is: \n%s * %s" % (args.mod, result.r, q))

    except Exception as e:
        logger.warning('Exception: %s' % e)
        if args.debug:
            traceback.print_exc()

    if not success:
        print('Factorization failed')


def main():
    parser = argparse.ArgumentParser(description='CM factorization script')
    parser.add_argument('--action', dest='action', action="store", default="factor",
                        help='Action to perform, options: factor, generate')

    parser.add_argument('--modulus', '-N', dest='mod', action='store', type=int, default=158697752795669080171615843390068686677,
                        help='Modulus to factorize')
    parser.add_argument('--disc', '-D', dest='disc', action='store', type=int, default=11,
                        help='D, the discriminant to compute factorization for')
    parser.add_argument('--prime-bits', dest='prime_bits', action='store', type=int, default=256,
                        help='Number of prime bits to generate')

    parser.add_argument('--timeout', dest='timeout', action="store", type=int, default=4*60,
                        help='Number of seconds for the factorization job, negative for no timeout')
    parser.add_argument('--qinv2', dest='qinv2', default=1, type=int,
                        help='Use optimized inversion algorithm (enabled by default)')
    parser.add_argument('--cheng', dest='cheng', default=1, type=int,
                        help='Use Cheng xgcd instead of norms (enabled by default)')

    parser.add_argument('--debug', dest='debug', action='store_const', const=True, default=False,
                        help='Debugging enabled')

    args = parser.parse_args()
    if args.action is None or args.action == 'factor':
        work_factor(args)
    elif args.action == 'generate':
        work_generate(args)
    else:
        raise ValueError('Unknown action: %s' % args.action)


if __name__ == "__main__":
    main()

