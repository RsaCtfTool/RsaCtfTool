#!/usr/bin/python
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

    def prime_factors(self):
        # Factorize n using factordb.com
        try:
            url_1 = 'http://www.factordb.com/index.php?query=%i'
            url_2 = 'http://www.factordb.com/index.php?id=%s'
            r = requests.get(url_1 % self.n)
            regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
            ids = regex.findall(r.text)
            p_id = ids[1]
            q_id = ids[2]
            regex = re.compile("value=\"([0-9]+)\"", re.IGNORECASE)
            r_1 = requests.get(url_2 % p_id)
            r_2 = requests.get(url_2 % q_id)
            self.p = int(regex.findall(r_1.text)[0])
            self.q = int(regex.findall(r_2.text)[0])
            if self.p == self.q == self.n:
                raise FactorizationError()
        except:
            raise FactorizationError()

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
        # Load public key
        key = open(args.publickey, 'rb').read()
        self.pubkeyfile = args.publickey
        self.pub_key = PublicKey(key)
        self.priv_key = None
        self.args = args
        self.unciphered = None
        # Load ciphertext
        if args.uncipher is not None:
            self.cipher = open(args.uncipher, 'rb').read().strip()
        else:
            self.cipher = None

        return 

    def hastads(self):
        # Hastad's attack
        if self.pub_key.e == 3 and self.args.uncipher is not None:
            orig = s2n(self.cipher)
            c = orig
            while True: 
                m = gmpy.root(c, 3)[0]
                if pow(m, 3, self.pub_key.n) == orig:
                    self.unciphered = n2s(m)
                    break
                c += self.pub_key.n
        return

    def factordb(self):
        # Factors available online?
        try:
            self.pub_key.prime_factors()
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

            return

        except FactorizationError:
            return

    def wiener(self):
        # this attack module can be optional
        try:
            from wiener_attack import WienerAttack
        except ImportError:
            if self.args.verbose:
                print "[*] Warning: Wiener attack module missing (wiener_attack.py)"
            return

        # Wiener's attack
        wiener = WienerAttack(self.pub_key.n, self.pub_key.e)
        if wiener.p is not None and wiener.q is not None:
            self.pub_key.p = wiener.p
            self.pub_key.q = wiener.q
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

    def fermat(self,fermat_timeout=60):
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

    def commonfactors(self):
        if self.args.uncipher:
            # Try an attack where the public key has a common factor with the ciphertext - sourcekris
            commonfactor = gcd(self.pub_key.n, s2n(self.cipher))
            
            if commonfactor > 1:
                self.pub_key.q = commonfactor
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q), 
                                           long(self.pub_key.e), long(self.pub_key.n))

                unciphered = self.priv_key.decrypt(self.cipher)

        return

    def pastctfprimes(self):
        primes = [long(x) for x in open('pastctfprimes.txt','r').readlines() if not x.startswith('#') and not x.startswith('\n')]
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

    def attack(self):
        # loop through implemented attack methods and conduct attacks
        for attack in self.implemented_attacks:
            if self.args.verbose:
                print "[*] Performing " + attack.__name__ + " attack."

            getattr(self, attack.__name__)()

            # check and print resulting private key
            if self.priv_key is not None:
                if self.args.private:
                    print self.priv_key
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

    implemented_attacks = [ hastads, factordb, pastctfprimes, noveltyprimes, smallq, wiener, commonfactors, fermat, siqs ]
    

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RSA CTF Tool Continued')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--publickey', help='public key file. You can use wildcards for multiple keys.')
    group.add_argument('--createpub', help='Take n and e from cli and just print a public key then exit', action='store_true')
    group.add_argument('--dumpkey', help='Just dump the RSA variables from a key - n,e,d,p,q', action='store_true')
    parser.add_argument('--uncipher', help='uncipher a file', default=None)
    parser.add_argument('--verbose', help='verbose mode (display n, e, p and q)', action='store_true')
    parser.add_argument('--private', help='Display private key if recovered', action='store_true')
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
        #print RSA.construct((args.n, args.e)).publickey().exportKey()
        key_data = open(args.key,'rb').read() 
        key = RSA.importKey(key_data)
        print "[*] n: " + str(key.n)
        print "[*] e: " + str(key.e)
        if key.has_private():
            print "[*] d: " + str(key.d)
            print "[*] p: " + str(key.p)
            print "[*] q: " + str(key.q)
        quit()

    # Multi Key case
    if '*' in args.publickey or '?' in args.publickey:
        # do multikey stuff
        pubkeyfilelist = glob(args.publickey)
        if args.verbose:
            print "[*] Multikey mode is EXPERIMENTAL."
            print "[*] Keys: " + repr(pubkeyfilelist)

        # naive case, just iterate the public keys
        attackobjs = []
        for p in pubkeyfilelist:
            if args.verbose:
                print 
                print "[*] Attacking key: " + p
            args.publickey = p # bit kludgey yes
            # build a list of attackobjects along the way
            attackobjs.append(RSAAttack(args))
            attackobjs[-1].attack()

        # check our array of RSAAttack objects then perform common factor attacks
        if args.verbose:
            print "[*] Performing multi key attacks."
        for x in attackobjs:
            for y in attackobjs:
                if x.pub_key.n <> y.pub_key.n:
                    g = gcd(x.pub_key.n, y.pub_key.n)
                    if g != 1:
                        # TODO: Finish this :P
                        print "[*] Found common factor in modulus for " + x.pubkeyfile + " and " + y.pubkeyfile
                        print "[*] Common factor: " + str(g)
                        #print x.pub_key.n
                        #print y.pub_key.n
    else:
        # Single key case
        attackobj = RSAAttack(args)
        attackobj.attack()

