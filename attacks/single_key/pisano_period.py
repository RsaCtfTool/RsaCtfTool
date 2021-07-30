#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integer factorization with pisano period
Heavily based on original repo https://github.com/wuliangshun/IntegerFactorizationWithPisanoPeriod/
White paper: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8901977
"""
import random
import time
from tqdm import tqdm
from lib.keys_wrapper import PrivateKey
from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import (
    powmod,
    mod,
    ilog10,
    ilog2,
    fib,
    trivial_factorization_with_n_phi,
)
from lib.utils import timeout, TimeoutError


class Fibonacci:
    def __init__(self, progress=False, verbose=True):
        self.progress = progress
        self.verbose = verbose

    def _fib_res(self, n, p):
        """ fibonacci sequence nth item modulo p """
        if n == 0:
            return (0, 1)
        a, b = self._fib_res(n >> 1, p)
        c = mod((mod(a, p) * mod(((b << 1) - a), p)), p)
        d = mod((powmod(a, 2, p) + powmod(b, 2, p)), p)
        if n & 1 == 0:
            return (c, d)
        return (d, mod((c + d), p))

    def get_n_mod_d(self, n, d, use="mersenne"):
        if n < 0:
            ValueError("Negative arguments not implemented")
        if use == "gmpy":
            return mod(fib(n), d)
        elif use == "mersenne":
            return powmod(2, n, d) - 1
        else:
            return self._fib_res(n, d)[0]

    def get_period_bigint(self, N, min_accept, xdiff, verbose=False):
        search_len = int(pow(N, (1.0 / 6) / 100))

        if search_len < min_accept:
            search_len = min_accept

        if self.verbose:
            print("Search_len: %d, log2(N): %d" % (search_len, ilog2(N)))

        starttime = time.time()
        diff = xdiff
        p_len = int((len(str(N)) + diff) >> 1) + 1
        begin = N - int("9" * p_len)
        if begin <= 0:
            begin = 1
        end = N + int("9" * p_len)

        if self.verbose:
            print("Search begin: %d, end: %d" % (begin, end))

        look_up = {}
        for x in tqdm(range(search_len), disable=(not self.progress)):
            look_up[self.get_n_mod_d(x, N)] = x

        if verbose:
            print("Searching...")

        while True:
            randi = random.randint(begin, end)
            res = self.get_n_mod_d(randi, N)
            if res > 0:
                if res in look_up:
                    res_n = look_up[res]
                    T = randi - res_n

                    if T & 1 == 0:
                        if self.get_n_mod_d(T, N) == 0:
                            td = int(time.time() - starttime)
                            if self.verbose:
                                print(
                                    "For N = %d Found T:%d, randi: %d, time used %f secs."
                                    % (N, T, randi, td)
                                )
                            return td, T, randi
                        else:
                            if self.verbose:
                                print(
                                    "For N = %d\n Found res: %d, res_n: %d , T: %d\n but failed!"
                                    % (N, res, res_n, T)
                                )
            else:
                if randi & 1 == 0:
                    T = randi
                    td = int(time.time() - starttime)
                    if self.verbose:
                        print(
                            "First shot, For N = %d Found T:%d, randi: %d, time used %f secs."
                            % (N, T, randi, td)
                        )
                    return td, T, randi

    def factorization(self, N, min_accept, xdiff):
        res = self.get_period_bigint(N, min_accept, xdiff)
        if res is not None:
            t, T, r = res
            return trivial_factorization_with_n_phi(N, T)


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """
        Pisano(mersenne) period factorization algorithm optimal for keys sub 70 bits in less than a minute.
        The attack is very similar to londahl's
        """
        Fib = Fibonacci(progress=progress)
        with timeout(self.timeout):
            try:
                B1, B2 = (
                    pow(10, (ilog10(publickey.n) // 2) - 4),
                    0,
                )  # Arbitrary selected bounds, biger b2 is more faster but more failed factorizations.
                try:
                    r = Fib.factorization(publickey.n, B1, B2)
                except OverflowError:
                    r = None
                if r is not None:
                    publickey.p, publickey.q = r
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
                return (None, None)
            except TimeoutError:
                return (None, None)
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCQwDQYJKoZIhvcNAQEBBQADEwAwEAIJVqCE2raBvB+lAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
