#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
RsaCtfTool-Continued - RSA CTF Cracking tool for simple CTF challenges
author: sourcekris (@CTFKris)

Original author's license below:
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
"""

from Crypto.PublicKey import RSA
import signal
import gmpy
from libnum import *
import requests
import re
import argparse
import os
import subprocess
from glob import glob


class FactorizationError(Exception):
    pass

class PublicKey(object):
    def __init__(self, key):
        """Create RSA key from input content
           :param key: public key file content
           :type key: string
        """
        pub = RSA.importKey(key)
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
        d = invmod(e,t)
        self.key = RSA.construct((n, e, d, p, q))

    def decrypt(self, cipher):
        """Uncipher data with private key
           :param cipher: input cipher
           :type cipher: string
        """
        return self.key.decrypt(cipher)

    def __str__(self):
        # Print armored private key
        return self.key.exportKey()

class RSAAttack(object):
    def __init__(self, args):
        if '*' in args.publickey or '?' in args.publickey:
            # get list of public keys from wildcard expression
            self.pubkeyfilelist = glob(args.publickey)
            self.args = args

            if args.verbose:
                print "[*] Multikey mode using keys: " + repr(self.pubkeyfilelist)

            # Initialize a list of objects by recursively calling this on each key
            self.attackobjs = []
            for pub in self.pubkeyfilelist:
                args.publickey = pub  # is this a kludge or is this elegant?
                self.attackobjs.append(RSAAttack(args))
        else:
            # Load single public key
            key = open(args.publickey, 'rb').read()
            self.pubkeyfile = args.publickey
            self.pub_key = PublicKey(key)
            self.priv_key = None
            self.displayed = False   # have we already spammed the user with this private key?
            self.args = args
            self.unciphered = None
            self.attackobjs = None  # This is how we'll know this object represents 1 key

            # Test if sage is working and if so, load additional sage based attacks
            if args.sageworks:
                self.implemented_attacks.append(self.smallfraction)
                self.implemented_attacks.append(self.boneh_durfee)
                self.implemented_attacks.append(self.ecm)           # make sure ECM always comes last!

            # Load ciphertext
            if args.uncipher is not None:
                self.cipher = open(args.uncipher, 'rb').read().strip()
            else:
                self.cipher = None
        return

    def hastads(self):
        # Hastad attack for low public exponent, this has found success for e = 3, and e = 5 previously
        if self.pub_key.e <= 11 and self.args.uncipher is not None:
            orig = s2n(self.cipher)
            c = orig
            while True: 
                m = gmpy.root(c, self.pub_key.e)[0]
                if pow(m, self.pub_key.e, self.pub_key.n) == orig:
                    self.unciphered = n2s(m)
                    break
                c += self.pub_key.n
        return

    def factordb(self):
        # if factordb returns some math to derive the prime, solve for p without using an eval
        def solveforp(equation):
            try:
                if '^' in equation: k,j = equation.split('^')
                if '-' in j: j,sub = j.split('-')
                eq = map(int, [k,j,sub])
                return pow(eq[0],eq[1])-eq[2]
            except Exception as e:
                if self.args.verbose:
                    print "[*] FactorDB gave something we couldn't parse sorry (%s). Got error: %s" % (equation,e)
                raise FactorizationError()

        # Factors available online?
        try:
            url_1 = 'http://www.factordb.com/index.php?query=%i'
            url_2 = 'http://www.factordb.com/index.php?id=%s'
            s = requests.Session()
            r = s.get(url_1 % self.pub_key.n)
            regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
            ids = regex.findall(r.text)
            p_id = ids[1]
            q_id = ids[2]
            # bugfix: See https://github.com/sourcekris/RsaCtfTool/commit/16d4bb258ebb4579aba2bfc185b3f717d2d91330#commitcomment-21878835
            regex = re.compile("value=\"([0-9\^\-]+)\"", re.IGNORECASE)
            r_1 = s.get(url_2 % p_id)
            r_2 = s.get(url_2 % q_id)
            key_p = regex.findall(r_1.text)[0]
            key_q = regex.findall(r_2.text)[0]
            self.pub_key.p = int(key_p) if key_p.isdigit() else solveforp(key_p)
            self.pub_key.q = int(key_q) if key_q.isdigit() else solveforp(key_q)
            if self.pub_key.p == self.pub_key.q == self.pub_key.n:
                raise FactorizationError()
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
            return
        except Exception as e:
            return

    def wiener(self):
        # this attack module can be optional based on sympy and wiener_attack.py existing
        try:
            from wiener_attack import WienerAttack
        except ImportError:
            if self.args.verbose:
                print "[*] Warning: Wiener attack module missing (wiener_attack.py) or SymPy not installed?"
            return

        # Wiener's attack
        wiener = WienerAttack(self.pub_key.n, self.pub_key.e)
        if wiener.p is not None and wiener.q is not None:
            self.pub_key.p = wiener.p
            self.pub_key.q = wiener.q
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

        return

    def ecm(self):
        # use elliptic curve method, may return a prime or may never return
        # only works if the sageworks() function returned True
        print "[*] ECM Method can run forever and may never succeed. Hit Ctrl-C to bail out."
        if self.args.ecmdigits:
            sageresult = int(subprocess.check_output(['sage', 'ecm.sage', str(self.pub_key.n),str(self.args.ecmdigits)]))
        else:
            sageresult = int(subprocess.check_output(['sage','ecm.sage',str(self.pub_key.n)]))

        if sageresult > 0:
            self.pub_key.p = sageresult
            self.pub_key.q = self.pub_key.n / self.pub_key.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
        return

    def boneh_durfee(self):
        # use boneh durfee method, should return a d value, else returns 0
        # only works if the sageworks() function returned True
        # many of these problems will be solved by the wiener attack module but perhaps some will fall through to here
        # TODO: get an example public key solvable by boneh_durfee but not wiener
        sageresult = int(subprocess.check_output(['sage','boneh_durfee.sage',str(self.pub_key.n),str(self.pub_key.e)]))

        if sageresult > 0:
            # use PyCrypto _slowmath rsa_construct to resolve p and q from d
            from Crypto.PublicKey import _slowmath
            tmp_priv = _slowmath.rsa_construct(long(self.pub_key.n), long(self.pub_key.e), d=long(sageresult))

            self.pub_key.p = tmp_priv.p
            self.pub_key.q = tmp_priv.q
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

        return

    def smallq(self):
        # Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
        for prime in primes(100000):
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))
        return

    def smallfraction(self):
        # Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
        # only works if the sageworks() function returned True
        sageresult = int(subprocess.check_output(['sage', 'smallfraction.sage',str(self.pub_key.n)]))
        if sageresult > 0:
            self.pub_key.p = sageresult
            self.pub_key.q = self.pub_key.n / self.pub_key.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
        return

    def fermat(self, fermat_timeout=60):
        # Try an attack where the primes are too close together from BKPCTF2016 - sourcekris
        # this attack module can be optional
        try:
            from fermat import fermat
        except ImportError:
            if self.args.verbose:
                print "[*] Warning: Fermat factorization module missing (fermat.py)"
            return

        try:
            with timeout(seconds=fermat_timeout):   
                self.pub_key.p, self.pub_key.q = fermat(self.pub_key.n)    
        except FactorizationError:
            return

        if self.pub_key.q is not None:
           self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                      long(self.pub_key.e), long(self.pub_key.n))

        return

    def noveltyprimes(self):
        # "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070" 
        # not all numbers in this form are prime but some are (25 digit is prime)
        maxlen = 25 # max number of digits in the final integer
        for i in range(maxlen-4):
            prime = long("3133" + ("3" * i) + "7")
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))        
        return

    def comfact_cn(self):
        # Try an attack where the public key has a common factor with the ciphertext - sourcekris
        if self.args.uncipher:
            commonfactor = gcd(self.pub_key.n, s2n(self.cipher))
            
            if commonfactor > 1:
                self.pub_key.q = commonfactor
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q), 
                                           long(self.pub_key.e), long(self.pub_key.n))

                unciphered = self.priv_key.decrypt(self.cipher)

        return

    def commonfactors(self):
        # Try to find the gcd between each pair of modulii and resolve the private keys if gcd > 1
        for x in self.attackobjs:
            for y in self.attackobjs:
                if x.pub_key.n <> y.pub_key.n:
                    g = gcd(x.pub_key.n, y.pub_key.n)
                    if g != 1:
                        if self.args.verbose and not x.displayed and not y.displayed:
                            print "[*] Found common factor in modulus for " + x.pubkeyfile + " and " + y.pubkeyfile

                        # update each attackobj with a private_key
                        x.pub_key.p = g
                        x.pub_key.q = x.pub_key.n / g
                        y.pub_key.p = g
                        y.pub_key.q = y.pub_key.n / g
                        x.priv_key = PrivateKey(long(x.pub_key.p),long(x.pub_key.q),
                                                long(x.pub_key.e), long(x.pub_key.n))
                        y.priv_key = PrivateKey(long(y.pub_key.p), long(y.pub_key.q),
                                                long(y.pub_key.e), long(y.pub_key.n))

                    # call attack method to print the private keys at the nullattack step or attack singularly
                    # depending on the success of the gcd operation
                    x.attack()
                    y.attack()

        return

    def pastctfprimes(self):
        path = os.path.dirname(os.path.abspath(__file__))
        pastctfprimes_path = os.path.join(path, 'pastctfprimes.txt')
        primes = [long(x) for x in open(pastctfprimes_path,'r').readlines() if not x.startswith('#') and not x.startswith('\n')]
        if self.args.verbose:
            print "[*] Loaded " + str(len(primes)) + " primes"
        for prime in primes:
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))        
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
            if self.args.verbose:
                print "[*] Warning: Yafu SIQS attack module missing (siqs.py)"
            return

        if self.pub_key.n.bit_length() > 1024:
            print "[*] Warning: Modulus too large for SIQS attack module"
            return
    

        siqsobj = SiqsAttack(self.args, self.pub_key.n)

        if siqsobj.checkyafu() and siqsobj.testyafu():
            siqsobj.doattack()

        if siqsobj.p and siqsobj.q:
            self.pub_key.q = siqsobj.q
            self.pub_key.p = siqsobj.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
        return

    def Pollard_p_1(self):
        # Pollard P minus 1 factoring, using the algorithm as described by https://math.berkeley.edu/~sagrawal/su14_math55/notes_pollard.pdf
        from p_1 import pollard_P_1

        # Pollard P-1 attack
        self.pub_key.p, self.pub_key.q = pollard_P_1(self.pub_key.n)

        if self.pub_key.q is not None:
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                      long(self.pub_key.e), long(self.pub_key.n))

        return

    def nullattack(self):
        # do nothing, used for multi-key attacks that succeeded so we just print the
        # private key without spending any time factoring
        return

    def attack(self):
        if self.attackobjs is not None:
            self.commonfactors()
        else:
            # loop through implemented attack methods and conduct attacks
            for attack in self.implemented_attacks:
                if self.args.verbose and "nullattack" not in attack.__name__:
                    print "[*] Performing " + attack.__name__ + " attack."

                getattr(self, attack.__name__)()

                # check and print resulting private key
                if self.priv_key is not None:
                    if self.args.private and not self.displayed:
                        print self.priv_key
                        self.displayed = True
                    break

                if self.unciphered is not None:
                    break

            # If we wanted to decrypt, do it now
            if self.args.uncipher is not None and self.priv_key is not None:
                    self.unciphered = self.priv_key.decrypt(self.cipher)
                    print "[+] Clear text : %s" % self.unciphered
            elif self.unciphered is not None:
                    print "[+] Clear text : %s" % self.unciphered
            else:
                if self.args.uncipher is not None:
                    print "[-] Sorry, cracking failed"

    implemented_attacks = [ nullattack,Pollard_p_1, hastads, factordb, pastctfprimes, noveltyprimes, smallq, wiener, comfact_cn, fermat, siqs ]

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

    if 'SageMath version' in sageversion:

        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RSA CTF Tool Continued')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--publickey', help='public key file. You can use wildcards for multiple keys.')
    group.add_argument('--createpub', help='Take n and e from cli and just print a public key then exit', action='store_true')
    group.add_argument('--dumpkey', help='Just dump the RSA variables from a key - n,e,d,p,q', action='store_true')
    parser.add_argument('--uncipher', help='uncipher a file', default=None)
    parser.add_argument('--verbose', help='verbose mode (display n, e, p and q)', action='store_true')
    parser.add_argument('--private', help='Display private key if recovered', action='store_true')
    parser.add_argument('--ecmdigits', type=int, help='Optionally an estimate as to how long one of the primes is for ECM method', default=None)
    parser.add_argument('--n', type=long, help='Specify the modulus in --createpub mode.')
    parser.add_argument('--e', type=long, help='Specify the public exponent in --createpub mode.')
    parser.add_argument('--key', help='Specify the input key file in --dumpkey mode.')

    args = parser.parse_args()

    # if createpub mode generate public key then quit
    if args.createpub:
        if args.n is None or args.e is None:
            raise Exception("Specify both a modulus and exponent on the command line. See --help for info.")
        print RSA.construct((args.n, args.e)).publickey().exportKey()
        quit()

    # if dumpkey mode dump the key components then quit
    if args.dumpkey:
        if args.key is None:
            raise Exception("Specify a key file to dump with --key. See --help for info.")

        key_data = open(args.key,'rb').read() 
        key = RSA.importKey(key_data)
        print "[*] n: " + str(key.n)
        print "[*] e: " + str(key.e)
        if key.has_private():
            print "[*] d: " + str(key.d)
            print "[*] p: " + str(key.p)
            print "[*] q: " + str(key.q)
        quit()

    if sageworks():
        args.sageworks = True
    else:
        args.sageworks = False

    attackobj = RSAAttack(args)
    attackobj.attack()

