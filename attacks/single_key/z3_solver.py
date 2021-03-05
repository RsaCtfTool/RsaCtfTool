#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import *
from gmpy2 import isqrt
from lib.utils import timeout, TimeoutError
from lib.keys_wrapper import PrivateKey

def z3_solve(n, timeout_amount):
    p = Int('x')
    q = Int('y')
    s = Solver()
    i = int(isqrt(n))
    s.add(p*q == n, p > 1, q > i, q > p)
    s.set("timeout", timeout_amount * 1000)
    try:
        s_check_output = s.check()
        print(check_output)
        res = s.model()
        return res[p],res[q]
    except:
        return None, None


def attack(attack_rsa_obj, publickey, cipher=[]):
    timeout_amount = attack_rsa_obj.args.timeout
    if not hasattr(publickey, "p"):
        publickey.p = None
    if not hasattr(publickey, "q"):
        publickey.q = None

    # solve with z3 theorem prover
    with timeout(timeout_amount):
        try:
            try:
                euler_res = z3_solve(publickey.n, timeout_amount)
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
