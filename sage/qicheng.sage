import sys
from sage.parallel.multiprocessing_sage import parallel_iter
from multiprocessing import cpu_count
sys.setrecursionlimit(10000)


def factor(n, attempts=50):
    r""" Try to factor n using Qi Cheng's elliptic curve algorithm and return the result.

    TESTS::
        sage: factor(8586738020906178596816665408975869027249332195806516889218842326669979457567897544415936583733118068451112024495528372623268891464850844330698707082078341676048316328425781368868164458486632570090121972627446596326046274266659293352906034163997023314644106659615348855576648233885381655772208214809201687506171743157882478565146018301168224250821080109298362928393693620666868337500513217122524859198701942611835138196019213020523307383514277039557237260096859973)
        134826985114673693079697889309176855021348273420672992955072560868299506854125722349531357991805652015840085409903545018244092326610812466869635572979633488227724165641914777716235431963802791410179554688486108196212276141821415175590671132382956670453821994294396707908761669407050042067400072453975327507467

        sage: factor(1444329727510154393553799612747635457542181563961160832013134005088873165794135221)
        74611921979343086722526424506387128972933
    """

    Consts = {}
    Consts['0'] = 0
    Consts['1'] = 1
    Consts['2'] = 2
    Consts['3'] = 3
    Consts['1728'] = 1728

    js = [0, (-2 ^ 5) ^ 3, (-2 ^ 5 * 3) ^ 3, (-2 ^ 5 * 3 * 5 * 11) ^ 3, (-2 ^ 6 * 3 * 5 * 23 * 29) ^ 3]

    def corefunc(n, js, Consts):
        R = Integers(n)

        for j in js:
            if j == Consts['0']:
                a = R.random_element()
                E = EllipticCurve([Consts['0'], a])

            else:
                a = R(j) / (R(Consts['1728']) - R(j))
                c = R.random_element()
                E = EllipticCurve([Consts['3'] * a * c ^ Consts['2'], Consts['2'] * a * c ^ Consts['3']])

            x = R.random_element()
            z = E.division_polynomial(n, x)
            g = gcd(z, n)
            if g > Consts['1']:
                return g

    cpus = cpu_count()
    if attempts > cpus:
        A = cpus
    else:
        A = attempts
    B = int(attempts / cpus)

    for i in range(0, B  + 1):
        inputs = [((n, js, Consts,), {})] * A
        for k, val in parallel_iter(A, corefunc, inputs):
            if val is not None:
                return val


if __name__ == "__main__":
    print(factor(Integer(sys.argv[1])))
