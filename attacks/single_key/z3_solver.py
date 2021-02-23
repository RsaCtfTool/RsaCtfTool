from z3 import *

from gmpy2 import isqrt

def z3_solve(n):
  p = Int('x')
  q = Int('y')
  s = Solver()
  i = int(isqrt(n))
  s.add(p*q == n, p > 1, q > i, q > p)
  print(s.check())
  res = s.model()
  return res[p],res[q]


def attack(attack_rsa_obj, publickey, cipher=[]):
    """Run attack with z3 method"""
    if not hasattr(publickey, "p"):
        publickey.p = None
    if not hasattr(publickey, "q"):
        publickey.q = None

    # solve with z3 theorem prover
    with timeout(attack_rsa_obj.args.timeout):
        try:
            try:
                euler_res = z3_solve(publickey.n)
            except:
                print("z3: Internal Error")
                return (None, None)
            if euler_res and len(euler_res) > 1:
                publickey.p, publickey.q = euler_res

            if publickey.q is not None:
                priv_key = PrivateKey(
                    int(publickey.p),
                    int(publickey.q),
                    int(publickey.e),
                    int(publickey.n),
                )
                return (priv_key, None)
        except TimeoutError:
            return (None, None)

    return (None, None)
