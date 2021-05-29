#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integer factorization with pisano period
Heavily based on original repo https://github.com/wuliangshun/IntegerFactorizationWithPisanoPeriod/
White paper: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8901977
"""
import random
import time
import sys
from lib.keys_wrapper import PrivateKey
from attacks.abstract_attack import AbstractAttack
from lib.rsalibnum import isqrt, gcd, powmod, is_prime, mod, ilog10, fib
from lib.utils import timeout, TimeoutError
sys.setrecursionlimit(5000)


class Fibonacci:
    def __init__(self):
        pass
    

    def _fib_res(self,n,p):
        """ fibonacci sequence nth item modulo p """
        if n == 0:
            return (0, 1)
        else:
            a, b = self._fib_res(n >> 1,p)
            c = mod((mod(a, p) * mod(((b << 1) - a), p)), p)
            d = mod((powmod(a, 2, p) + powmod(b, 2, p)), p)
            if n & 1 == 0: 
                return (c, d)
            else:
                return (d, mod((c + d), p))


    def get_n_mod_d(self,n,d, use = 'mersenne'):
        if n < 0:
            ValueError("Negative arguments not implemented")
        if use == 'gmpy':
            return mod(fib(n), d)
        elif use == 'mersenne':
            return mod(powmod(2,n, d)-1, d)
        else:
            return self._fib_res(n,d)[0]

    
    def binary_search(self,L,n):
        """ Finds item index in O(log2(N)) """ 
        left = 0
        right = len(L) - 1
        while left <= right:
            mid=(left + right) >> 1
            if n == L[mid]:
                return mid
            elif n < L[mid]:
                right = mid - 1
            else:
                left = mid + 1
        return -1
    
    
    def sort_list(self,L):
        from operator import itemgetter
        indices, L_sorted = zip(*sorted(enumerate(L), key=itemgetter(1)))
        return list(L_sorted),list(indices)


    def get_period_bigint(self, N, min_accept, xdiff, verbose = False):            
        search_len = int(pow(N, (1.0 / 6) / 100))
        
        if search_len < min_accept:
            search_len = min_accept
  
        if verbose:
            print('search_len:%d'%(search_len))
        
        starttime = time.time()
        diff = xdiff 
        p_len = int((len(str(N)) + diff) >> 1) + 1
        begin = N - int('9'*p_len) 
        if begin <= 0:
            begin = 1
        end = N + int('9' * p_len)
    
        if verbose:    
            print('search begin:%d,end:%d'%(begin, end))
                
        rs = [self.get_n_mod_d(x, N) for x in range(search_len)]
        rs_sort, rs_indices = self.sort_list(rs)

        if verbose:    
            #print(rs, rs_sort, rs_indices)        
            print('sort complete! time used: %f secs' % (time.time() - starttime))
                
        T = 0
        has_checked_list = []

        while True:       
            randi = random.randint(begin,end)            
            if (not randi in has_checked_list):
                has_checked_list.append(randi)
            
                res = self.get_n_mod_d(randi, N)
                if res > 0:
                    inx = self.binary_search(rs_sort, res)
                    if inx > -1:                
                        res_n = rs_indices[inx]
                        T = randi - res_n
                     
                        if self.get_n_mod_d(T, N) == 0:
                            td = int(time.time() - starttime)
                            if verbose:
                                print('For N = %d Found T:%d, randi: %d, time used %f secs.' % (N , T, randi, td))
                            return td, T, randi
                        else:
                            if verbose:
                                print('For N = %d\n Found res: %d, inx: %d, res_n: %d , T: %d\n but failed!' % (N, res, inx, res_n, T))
                else:
                    T = randi
                    td = int(time.time() - starttime)
                    if verbose:
                        print('First shot, For N = %d Found T:%d, randi: %d, time used %f secs.' % (N , T, randi, td))
                    return td, T, randi


    def _trivial_factorization_with_n_phi(self, N, phi):
        p1 = []
        d2 = N << 2

        phi2 = pow(phi,2)
        phi2p4d = phi2 + d2
        phi2m4d = phi2 - d2

        if phi2m4d > 0:
            iphi2m4d = isqrt(phi2m4d)
            p1.append(phi + iphi2m4d)
            p1.append(phi - iphi2m4d)

        if phi2p4d > 0:
            iphi2p4d = isqrt(phi2p4d)
            p1.append(phi + iphi2p4d)
            p1.append(phi - iphi2p4d)

        if phi2m4d > 0:
            iphi2m4d = isqrt(phi2m4d)
            p1.append(-phi + iphi2m4d)
            p1.append(-phi - iphi2m4d)

        if phi2p4d > 0:
            iphi2p4d = isqrt(phi2p4d)
            p1.append(-phi + iphi2p4d)
            p1.append(-phi - iphi2p4d)

        for p in p1:
            g = gcd((p >> 1),N)
            if N > g > 1:
                return int(g),int(N//g)
   

    def factorization(self, N, min_accept, xdiff, verbose=True):
        res = self.get_period_bigint(N, min_accept, xdiff, verbose=verbose) 
        if res != None:
            t, T, r = res 
            phi = abs(N - T) + 1 # phi = (p-1)(q-1) => (pq)-(p-q)+1 => N-(p-q)+1 so T = p-q
            return self._trivial_factorization_with_n_phi(N, phi)


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]

    def attack(self, publickey, cipher=[], progress=True):
        """
        Pisano period factorization algorithm optimal for keys sub 47 bits in less than a minute.
        """
        Fib = Fibonacci()
        with timeout(self.timeout):
            try:
                B1, B2 = pow(10,(ilog10(publickey.n)//2)-3), 2 # Arbitrary selected bounds, biger b2 is more faster but more failed factorizations.
                r = Fib.factorization(publickey.n,B1,B2)
                if r != None:
                    publickey.p, publickey.q = r
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
                else:
                    return (None, None)
            except TimeoutError:
                return (None, None)
        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey
        key_data = """-----BEGIN PUBLIC KEY-----
MCMwDQYJKoZIhvcNAQEBBQADEgAwDwIIDWT8rEw6XZMCAwEAAQ==
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
