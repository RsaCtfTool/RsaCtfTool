#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
Additionnal contributors :
@CTFKris (sourcekris)
"""

from Crypto.PublicKey import RSA
import signal
import gmpy2

from Crypto.Util.number import bytes_to_long, long_to_bytes

from rsalibnum import *
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import re
import argparse
import os
import subprocess
from glob import glob
import tempfile
import sys
import itertools

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

sys.setrecursionlimit(2000)
if sys.version_info < (3, 0):
    int = long


class FactorizationError(Exception):
    pass


class PublicKey(object):
    def __init__(self, key):
        """Create RSA key from input content
           :param key: public key file content
           :type key: string
        """
        try:
            pub = RSA.importKey(key)
        except ValueError as e:
            print(e)
            sys.exit(1)
        self.n = pub.n
        self.e = pub.e
        self.key = key

    def __str__(self):
        # Print armored public key
        return self.key


class PrivateKey(object):
    def __init__(self, p, q, e, n):
        """Create private key from base components
           :param p: extracted from n
           :param q: extracted from n
           :param e: exponent
           :param n: n from public key
        """

        t = (p-1)*(q-1)
        d = invmod(e, t)
        self.key = RSA.construct((n, e, d, p, q))

    def decrypt(self, cipher):
        """Uncipher data with private key
           :param cipher: input cipher
           :type cipher: string
        """

        try:
            tmp_priv_key = tempfile.NamedTemporaryFile()
            with open(tmp_priv_key.name, "wb") as tmpfd:
                tmpfd.write(str(self).encode('utf8'))
            tmp_priv_key_name = tmp_priv_key.name

            tmp_cipher = tempfile.NamedTemporaryFile()
            with open(tmp_cipher.name, "wb") as tmpfd:
                tmpfd.write(cipher)
            tmp_cipher_name = tmp_cipher.name

            with open('/dev/null') as DN:
                openssl_result = subprocess.check_output(['openssl',
                                                          'rsautl',
                                                          '-raw',
                                                          '-decrypt',
                                                          '-in',
                                                          tmp_cipher_name,
                                                          '-inkey',
                                                          tmp_priv_key_name],
                                                         stderr=DN)
                return openssl_result
        except:
            return self.key.decrypt(cipher)

    def __str__(self):
        # Print armored private key
        return self.key.exportKey().decode("utf-8")


class Qone(int):
    """Represents a value of 1 for prime q, and if you try to calculate phi(q)
    by doing q-1 it gives the correct result of 1."""
    def __sub__(a, b):
        assert a == 1
        assert b == 1
        return 1


class PrimeKey(PrivateKey):
    """A private key for when n is prime."""
    def __init__(self, n, e):
        assert gmpy2.is_prime(n)
        phi = n - 1
        d = invmod(e, phi)
        p = n
        q = Qone(1)
        self.key = RSA.RSAImplementation(use_fast_math=False).construct((n, e, d, p, q))


class RSAAttack(object):
    def __init__(self, args):
        if '*' in args.publickey or '?' in args.publickey:
            # get list of public keys from wildcard expression
            self.pubkeyfilelist = glob(args.publickey)
            self.args = args

            if args.verbose:
                print("[*] Multikey mode using keys: " + repr(self.pubkeyfilelist))

            self.attackobjs = []

            # Try to build new key if e is huge (so d is small) and after try wiener on this new key
            self.same_n_huge_e_attack()

            # Initialize a list of objects by recursively calling this on each key
            for pub in self.pubkeyfilelist:
                args.publickey = pub  # is this a kludge or is this elegant?
                self.attackobjs.append(RSAAttack(args))

        else:
            # Load single public key
            if not isinstance(args.publickey, str):
                args.publickey = args.publickey.name

            key = open(args.publickey, 'rb').read()
            self.pubkeyfile = args.publickey
            self.pub_key = PublicKey(key)
            self.priv_key = None
            self.displayed = False   # have we already spammed the user with this private key?
            self.args = args
            self.unciphered = None
            self.attackobjs = None  # This is how we'll know this object represents 1 key

            # Read n/e from publickey file
            if not args.n or not args.e:
                pkey = PublicKey(key)
                if not args.n:
                    args.n = pkey.n
                if not args.e:
                    args.e = pkey.e

            # Test if sage is working and if so, load additional sage based attacks
            if args.sageworks:
                self.implemented_attacks.append(self.smallfraction)
                self.implemented_attacks.append(self.boneh_durfee)
                self.implemented_attacks.append(self.qicheng)
                self.implemented_attacks.append(self.ecm)           # make sure ECM always comes last!

            # Load ciphertext
            if args.uncipher is not None:
                self.cipher = args.uncipher
            else:
                self.cipher = None
        return

    def same_n_huge_e_attack(self):
        parsed_keys = []
        for k in self.pubkeyfilelist:
            key = open(k, 'rb').read()
            parsed_keys.append(PublicKey(key))

        if len(set([_.n for _ in parsed_keys])) == 1:
            new_e = 1
            for k in parsed_keys:
                new_e = new_e * k.e
            tmpfile = tempfile.NamedTemporaryFile()
            with open(tmpfile.name, "wb") as tmpfd:
                tmpfd.write(RSA.construct((parsed_keys[0].n, new_e)).publickey().exportKey())
            self.same_n_huge_e = tmpfile
            return True
        else:
            return None

    def hastads(self):
        # Hastad attack for low public exponent, this has found success for e = 3, and e = 5 previously
        if self.pub_key.e <= 11 and self.cipher is not None:
            orig = s2n(self.cipher)
            c = orig
            while True:
                m = gmpy2.iroot(c, self.pub_key.e)[0]
                if pow(m, self.pub_key.e, self.pub_key.n) == orig:
                    self.unciphered = n2s(m)
                    break
                c += self.pub_key.n
        return

    def factordb(self):
        # if factordb returns some math to derive the prime, solve for p without using an eval
        def solveforp(equation):
            try:
                if '^' in equation:
                    k, j = equation.split('^')
                if '-' in j:
                    j, sub = j.split('-')
                eq = list(map(int, [k, j, sub]))
                return pow(eq[0], eq[1])-eq[2]
            except Exception as e:
                if self.args.verbose:
                    print("[*] FactorDB gave something we couldn't parse sorry (%s). Got error: %s" % (equation, e))
                raise FactorizationError()

        # Factors available online?
        try:
            url_1 = 'http://factordb.com/index.php?query=%i'
            url_2 = 'http://factordb.com/index.php?id=%s'
            s = requests.Session()
            r = s.get(url_1 % self.pub_key.n, verify=False)
            regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
            ids = regex.findall(r.text)

            if len(ids) < 3:
                # Factordb does not have at least two factors
                return

            p_id = ids[1]
            q_id = ids[2]
            # bugfix: See https://github.com/sourcekris/RsaCtfTool/commit/16d4bb258ebb4579aba2bfc185b3f717d2d91330#commitcomment-21878835
            regex = re.compile("value=\"([0-9\^\-]+)\"", re.IGNORECASE)
            r_1 = s.get(url_2 % p_id, verify=False)
            r_2 = s.get(url_2 % q_id, verify=False)
            key_p = regex.findall(r_1.text)[0]
            key_q = regex.findall(r_2.text)[0]
            self.pub_key.p = int(key_p) if key_p.isdigit() else solveforp(key_p)
            self.pub_key.q = int(key_q) if key_q.isdigit() else solveforp(key_q)
            if self.pub_key.p == self.pub_key.q == self.pub_key.n:
                raise FactorizationError()
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))
            return
        except Exception as e:
            return


    def prime_n(self):
        if gmpy2.is_prime(self.pub_key.n):
            self.priv_key = PrimeKey(self.pub_key.n, self.pub_key.e)


    def wiener(self):
        # this attack module can be optional based on sympy and wiener_attack.py existing
        try:
            from wiener_attack import WienerAttack
        except ImportError:
            print("[!] Warning: Wiener attack module missing (wiener_attack.py) or SymPy not installed?")
            return

        # Wiener's attack
        wiener = WienerAttack(self.pub_key.n, self.pub_key.e)
        if wiener.p is not None and wiener.q is not None:
            self.pub_key.p = wiener.p
            self.pub_key.q = wiener.q
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return

    def primefac(self, primefac_timeout=45):
        # this attack rely on primefac
        try:
            from primefac import primefac
        except ImportError:
            print("[!] Warning: primefac attack module missing")
            return

        # use primefac
        try:
            with timeout(seconds=primefac_timeout):
                result = list(primefac(self.pub_key.n, timeout=primefac_timeout))
        except FactorizationError :
            return

        if len(result) == 2:
            self.pub_key.p = int(result[0])
            self.pub_key.q = int(result[1])
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return

    def ecm(self):
        # use elliptic curve method, may return a prime or may never return
        # only works if the sageworks() function returned True
        print("[*] ECM Method can run forever and may never succeed. Hit Ctrl-C to bail out.")
        try:
            if self.args.ecmdigits:
                sageresult = int(subprocess.check_output(['sage', 'ecm.sage', str(self.pub_key.n), str(self.args.ecmdigits)]))
            else:
                sageresult = int(subprocess.check_output(['sage', 'ecm.sage', str(self.pub_key.n)]))
        except subprocess.CalledProcessError:
            return
        if sageresult > 0:
            self.pub_key.p = sageresult
            self.pub_key.q = self.pub_key.n // self.pub_key.p
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))
        return

    def boneh_durfee(self):
        # use boneh durfee method, should return a d value, else returns 0
        # only works if the sageworks() function returned True
        # many of these problems will be solved by the wiener attack module but perhaps some will fall through to here
        # TODO: get an example public key solvable by boneh_durfee but not wiener
        try:
            sageresult = int(subprocess.check_output(['sage', 'boneh_durfee.sage',
                                                      str(self.pub_key.n), str(self.pub_key.e)]))
        except subprocess.CalledProcessError:
            return
        if sageresult > 0:
            # use PyCrypto _slowmath rsa_construct to resolve p and q from d
            from Crypto.PublicKey import _slowmath
            tmp_priv = _slowmath.rsa_construct(int(self.pub_key.n), int(self.pub_key.e), d=int(sageresult))

            self.pub_key.p = tmp_priv.p
            self.pub_key.q = tmp_priv.q
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return

    def qicheng(self):
        # Qi Cheng - A New Class of Unsafe Primes
        try:
            sageresult = int(subprocess.check_output(['sage', 'qicheng.sage', str(self.pub_key.n)]))
        except subprocess.CalledProcessError:
            return

        if sageresult > 0:
            self.pub_key.p = sageresult
            self.pub_key.q = self.pub_key.n // sageresult
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return


    def smallq(self):
        # Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
        for prime in primes(100000):
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n // self.pub_key.q
                self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                           int(self.pub_key.e), int(self.pub_key.n))
        return

    def smallfraction(self):
        # Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
        # only works if the sageworks() function returned True
        try:
            sageresult = int(subprocess.check_output(['sage', 'smallfraction.sage', str(self.pub_key.n)]))
            if sageresult > 0:
                self.pub_key.p = sageresult
                self.pub_key.q = self.pub_key.n // self.pub_key.p
                self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                           int(self.pub_key.e), int(self.pub_key.n))
        except subprocess.CalledProcessError:
            return
        return

    def fermat(self, fermat_timeout=10):
        # Try an attack where the primes are too close together from BKPCTF2016 - sourcekris
        # this attack module can be optional
        try:
            from fermat import fermat
        except ImportError:
            print("[!] Warning: Fermat factorization module missing (fermat.py)")
            return

        try:
            with timeout(seconds=fermat_timeout):
                self.pub_key.p, self.pub_key.q = fermat(self.pub_key.n)
        except FactorizationError:
            return

        if self.pub_key.q is not None:
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return

    def londahl(self, londahl_b=20000000):
        # Another attack for primes that are too close together.
        # https://grocid.net/2017/09/16/finding-close-prime-factorizations/
        # `b` is the size of the lookup dictionary to build.
        try:
            import londahl
        except ImportError:
            print("[!] Warning: Londahl factorization module missing (londahl.py)")
            return

        factors = londahl.close_factor(self.pub_key.n, londahl_b)

        if factors is not None:
            self.pub_key.p, self.pub_key.q = factors
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return
    def noveltyprimes(self):
        # "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070"
        # not all numbers in this form are prime but some are (25 digit is prime)
        maxlen = 25  # max number of digits in the final integer
        for i in range(maxlen-4):
            prime = int("3133" + ("3" * i) + "7")
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n // self.pub_key.q
                self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                           int(self.pub_key.e), int(self.pub_key.n))
        return

    def comfact_cn(self):
        # Try an attack where the public key has a common factor with the ciphertext - sourcekris
        if self.cipher:
            commonfactor = gcd(self.pub_key.n, s2n(self.cipher))

            if commonfactor > 1:
                self.pub_key.q = commonfactor
                self.pub_key.p = self.pub_key.n // self.pub_key.q
                self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                           int(self.pub_key.e), int(self.pub_key.n))

                unciphered = self.priv_key.decrypt(self.cipher)

        return

    def commonfactors(self):
        # Try to find the gcd between each pair of moduli and resolve the private keys if gcd > 1
        for x, y in itertools.combinations(self.attackobjs, r=2):
            if x.pub_key.n != y.pub_key.n:
                g = gcd(x.pub_key.n, y.pub_key.n)
                if g != 1:
                    if self.args.verbose and not x.displayed and not y.displayed:
                        print("[*] Found common factor in modulus for " + x.pubkeyfile + " and " + y.pubkeyfile)

                    # update each attackobj with a private_key
                    x.pub_key.p = g
                    x.pub_key.q = x.pub_key.n // g
                    y.pub_key.p = g
                    y.pub_key.q = y.pub_key.n // g
                    x.priv_key = PrivateKey(int(x.pub_key.p), int(x.pub_key.q),
                                            int(x.pub_key.e), int(x.pub_key.n))
                    y.priv_key = PrivateKey(int(y.pub_key.p), int(y.pub_key.q),
                                            int(y.pub_key.e), int(y.pub_key.n))

                    # call attack method to print the private keys at the nullattack step
                    x.attack()
                    y.attack()

        # attack singularly if gcd operation was not successful
        for ao in self.attackobjs:
            ao.attack()

        return

    def pastctfprimes(self):
        path = os.path.dirname(os.path.abspath(__file__))
        pastctfprimes_path = os.path.join(path, 'pastctfprimes.txt')
        primes = [int(x) for x in open(pastctfprimes_path, 'r').readlines() if not x.startswith('#') and not x.startswith('\n')]
        if self.args.verbose:
            print("[*] Loaded " + str(len(primes)) + " primes")
        for prime in primes:
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n // self.pub_key.q
                self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                           int(self.pub_key.e), int(self.pub_key.n))
        return

    def commonmodulus(self):
        # NYI requires support for multiple public keys
        return

    def prime_modulus(self):
        # an attack where the modulus is not a composite number, so the math is unique
        # NYI
        return

    def siqs(self):
        # attempt a Self-Initializing Quadratic Sieve
        # this attack module can be optional
        try:
            from siqs import SiqsAttack
        except ImportError:
            print("[!] Warning: Yafu SIQS attack module missing (siqs.py)")
            return

        if self.pub_key.n.bit_length() > 1024:
            print("[!] Warning: Modulus too large for SIQS attack module")
            return

        siqsobj = SiqsAttack(self.args, self.pub_key.n)

        if siqsobj.checkyafu() and siqsobj.testyafu():
            siqsobj.doattack()

        if siqsobj.p and siqsobj.q:
            self.pub_key.q = siqsobj.q
            self.pub_key.p = siqsobj.p
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))
        return

    def Pollard_p_1(self):
        # Pollard P minus 1 factoring, using the algorithm as described by https://math.berkeley.edu/~sagrawal/su14_math55/notes_pollard.pdf
        from p_1 import pollard_P_1

        if not hasattr(self.pub_key, "p"):
            self.pub_key.p = None
        if not hasattr(self.pub_key, "q"):
            self.pub_key.q = None

        # Pollard P-1 attack
        poll_res = pollard_P_1(self.pub_key.n)
        if poll_res and len(poll_res) > 1:
            self.pub_key.p, self.pub_key.q = poll_res

        if self.pub_key.q is not None:
            self.priv_key = PrivateKey(int(self.pub_key.p), int(self.pub_key.q),
                                       int(self.pub_key.e), int(self.pub_key.n))

        return

    def nullattack(self):
        # do nothing, used for multi-key attacks that succeeded so we just print the
        # private key without spending any time factoring
        return

    def mersenne_primes(self):
        p = q = None
        mersenne_tab = [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521,
                        607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941,
                        11213, 19937, 21701, 23209, 44497, 86243, 110503,
                        132049, 216091, 756839, 859433, 1257787, 1398269,
                        2976221, 3021377, 6972593, 13466917, 20336011,
                        24036583, 25964951, 30402457, 32582657, 37156667,
                        42643801, 43112609, 57885161, 74207281, 77232917]
        for mersenne_prime in mersenne_tab:
            if self.pub_key.n % ((2**mersenne_prime)-1) == 0:
                p = (2**mersenne_prime)-1
                q = self.pub_key.n // ((2**mersenne_prime)-1)
                break
        if p is not None and q is not None:
            self.priv_key = PrivateKey(int(p), int(q),
                                       int(self.pub_key.e),
                                       int(self.pub_key.n))
        return

    def attack(self):
        if self.attackobjs is not None:
            self.commonfactors()
            try:
                if self.same_n_huge_e:
                    args.attackobjs = None
                    args.publickey = self.same_n_huge_e
                    RSAAttack(args).attack()
            except AttributeError:
                pass
        else:
            # loop through implemented attack methods and conduct attacks
            for attack in self.implemented_attacks:
                if self.args.attack is not None and self.args.attack == attack.__name__:
                    if self.args.verbose:
                        print("[*] Performing " + attack.__name__ + " attack.")
                    getattr(self, attack.__name__)()
                elif self.args.attack is None or (self.args.attack is not None and self.args.attack == "all"):
                    if self.args.verbose and "nullattack" not in attack.__name__:
                        print("[*] Performing " + attack.__name__ + " attack.")
                    getattr(self, attack.__name__)()

                # check and print resulting private key
                if self.priv_key is not None:
                    if self.args.private and not self.displayed:
                        print(self.priv_key)
                        self.displayed = True

                    break

                if self.unciphered is not None:
                    break

            # If we wanted to decrypt, do it now
            if self.cipher and self.priv_key is not None:
                    self.unciphered = self.priv_key.decrypt(self.cipher)
                    print("[+] Clear text : %s" % str(self.unciphered))
            elif self.unciphered is not None:
                    print("[+] Clear text : %s" % str(self.unciphered))
            else:
                if self.cipher is not None and self.args.attack is None:
                    print("[-] Sorry, cracking failed")

            if self.priv_key is None and self.args.private:
                print("[-] Sorry, cracking failed")

    implemented_attacks = [nullattack, hastads, prime_n, factordb, pastctfprimes,
                           mersenne_primes, noveltyprimes, smallq, wiener,
                           comfact_cn, primefac, fermat, siqs, Pollard_p_1,
                           londahl]


# source http://stackoverflow.com/a/22348885
class timeout:
    def __init__(self, seconds=10, error_message='[-] Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise FactorizationError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


def sageworks():
    # Check if sage is installed and working
    try:
        sageversion = subprocess.check_output(['sage', '-v'])
    except OSError:
        return False

    if 'SageMath version' in sageversion.decode('utf-8'):

        return True
    else:
        return False


def loadkeys(keys):
    """ Load one or more keys
    """
    return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RSA CTF Tool')
    parser.add_argument('--publickey', help='public key file. You can use wildcards for multiple keys.')
    parser.add_argument('--createpub', help='Take n and e from cli and just print a public key then exit', action='store_true')
    parser.add_argument('--dumpkey', help='Just dump the RSA variables from a key - n,e,d,p,q', action='store_true')
    parser.add_argument('--ext', help='Extended dump of RSA private variables in --dumpkey mode - dp,dq,pinv,qinv).', action='store_true')
    parser.add_argument('--uncipherfile', help='uncipher a file', default=None)
    parser.add_argument('--uncipher', help='uncipher a cipher', default=None)
    parser.add_argument('--verbose', help='verbose mode (display n, e, p and q)', action='store_true')
    parser.add_argument('--private', help='Display private key if recovered', action='store_true')
    parser.add_argument('--ecmdigits', type=int, help='Optionally an estimate as to how long one of the primes is for ECM method', default=None)
    parser.add_argument('-n', help='Specify the modulus. format : int or 0xhex')
    parser.add_argument('-p', help='Specify the first prime number. format : int or 0xhex')
    parser.add_argument('-q', help='Specify the second prime number. format : int or 0xhex')
    parser.add_argument('-e', help='Specify the public exponent. format : int or 0xhex')
    parser.add_argument('--key', help='Specify the input key file in --dumpkey mode.')
    attacks_list = [_.__name__ for _ in RSAAttack.implemented_attacks if _.__name__ is not "nullattack"] + ["all"]
    parser.add_argument('--attack', help='Specify the attack mode.', default="all", choices=attacks_list)

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Parse longs if exists
    if args.p is not None:
        if args.p.startswith("0x"):
            args.p = int(args.p, 16)
        else:
            args.p = int(args.p)

    if args.q is not None:
        if args.q.startswith("0x"):
            args.q = int(args.q, 16)
        else:
            args.q = int(args.q)

    if args.p and args.q is not None:
       args.n = args.p * args.q
    elif args.n is not None:
        if args.n.startswith("0x"):
            args.n = int(args.n, 16)
        else:
            args.n = int(args.n)

    if args.e is not None:
        if args.e.startswith("0x"):
            args.e = int(args.e, 16)
        else:
            args.e = int(args.e)

    # if we have uncipher but no uncipherfile
    if args.uncipher is not None:
        if args.uncipher.startswith("0x"):
            args.uncipher = int(args.uncipher, 16)
        else:
            args.uncipher = int(args.uncipher)
        args.uncipher = n2s(args.uncipher)

    elif args.uncipherfile is not None:
        cipher = open(args.uncipherfile, 'rb').read()
        args.uncipher = cipher

    # If we have n and one of p and q, calculated the other
    if args.n and (args.p or args.q):
        if args.p and not args.q:
            args.q = args.n // args.p
        if args.q and not args.p:
            args.p = args.n // args.q

    # If we already have all informations
    if args.p is not None and args.q is not None and args.e is not None:
        try:
            priv_key = PrivateKey(args.p, args.q, args.e, args.n)
        except ValueError:
            if args.verbose:
                print("[!] No invmod for e and t, maybe an error in your args ?")
            sys.exit(0)
        if args.private:
            print(priv_key)

        if args.createpub:
            print(RSA.construct((args.n, args.e)).publickey().exportKey())

        if args.uncipher is not None:
            unciphered = priv_key.decrypt(args.uncipher)
            print("[+] Clear text : %s" % unciphered)

        quit()

    # if createpub mode generate public key then quit
    if args.createpub:
        if (args.n is None and (args.p is None or args.q is None)) or args.e is None:
            raise Exception("Specify both a modulus and exponent on the command line. See --help for info.")

        print(RSA.construct((args.n, args.e)).publickey().exportKey().decode("utf-8"))
        quit()

    # if dumpkey mode dump the key components then quit
    if args.dumpkey:
        if args.key is None:
            raise Exception("Specify a key file to dump with --key. See --help for info.")

        key_data = open(args.key, 'rb').read()
        key = RSA.importKey(key_data)
        print("[*] n: " + str(key.n))
        print("[*] e: " + str(key.e))
        if key.has_private():
            print("[*] d: " + str(key.d))
            print("[*] p: " + str(key.p))
            print("[*] q: " + str(key.q))
            if args.ext:
                dp = key.d % (key.p - 1)
                dq = key.d % (key.q - 1)
                pinv = invmod(key.p, key.q)
                qinv = invmod(key.q, key.p)
                print("[*] dp: " + str(dp))
                print("[*] dq: " + str(dq))
                print("[*] pinv: " + str(pinv))
                print("[*] qinv: " + str(qinv))

        quit()

    if sageworks():
        args.sageworks = True
    else:
        args.sageworks = False

    tmpfile = None
    if args.publickey is None and args.e is not None and args.n is not None:
        tmpfile = tempfile.NamedTemporaryFile()
        with open(tmpfile.name, "wb") as tmpfd:
            tmpfd.write(RSA.construct((args.n, args.e)).publickey().exportKey())
        args.publickey = tmpfile.name

    attackobj = RSAAttack(args)
    attackobj.attack()
