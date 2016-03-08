#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
"""

from Crypto.PublicKey import RSA
from wiener_attack import WienerAttack
from fermat import fermat
import signal
import gmpy
from libnum import *
import requests
import re
import argparse


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
        #raise FactorizationError() # uncomment this to skip factordb during testing
        """Factorize n using factordb.com
        """
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
        """Print armored public key
        """
        return self.key


class PrivateKey(object):
    def __init__(self, p, q, e, n):
        """Create private key from base components
           :param p: extracted from n
           :type p: int
           :param q: extracted from n
           :type q: int
           :param e: exponent
           :type e: int
           :param n: n from public key
           :type n: int
        """
        t = (p-1)*(q-1)
        d = self.find_inverse(e, t)
        self.key = RSA.construct((n, e, d, p, q))

    def decrypt(self, cipher):
        """Uncipher data with private key
           :param cipher: input cipher
           :type cipher: string
        """
        return self.key.decrypt(cipher)

    def __str__(self):
        """Print armored private key
        """
        return self.key.exportKey()

    def eea(self, a, b):
        if b == 0:
            return (1, 0)
        (q, r) = (a//b, a % b)
        (s, t) = self.eea(b, r)
        return (t, s-(q * t))

    def find_inverse(self, x, y):
        inv = self.eea(x, y)[0]
        if inv < 1:
            inv += y
        return inv

class TimeoutError(Exception):
	pass
# source http://stackoverflow.com/a/22348885
class timeout:
    def __init__(self, seconds=1, error_message='[-] Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)


if __name__ == "__main__":
    """Main method (entrypoint)
    """
    parser = argparse.ArgumentParser(description='RSA CTF Tool')
    parser.add_argument('--publickey',
                        dest='public_key',
                        help='public key file',
                        required=True)
    parser.add_argument('--uncipher',
                        dest='uncipher',
                        help='uncipher a file',
                        default=None)
    parser.add_argument('--verbose',
                        dest='verbose',
                        help='verbose mode (display n, e, p and q)',
                        action='store_true')
    parser.add_argument('--private',
                        dest='private',
                        help='Display private key if recovered',
                        action='store_true')

    args = parser.parse_args()

    # Open cipher file
    unciphered = None
    if args.uncipher is not None:
        cipher = open(args.uncipher, 'r').read().strip()

    # Load public key
    key = open(args.public_key, 'r').read()
    pub_key = PublicKey(key)
    priv_key = None

    # Hastad's attack
    if pub_key.e == 3 and args.uncipher is not None:
        if args.verbose:
            print "[*] Try Hastad's attack"

        orig = s2n(cipher)
        c = orig
        while True:
            m = gmpy.root(c, 3)[0]
            if pow(m, 3, pub_key.n) == orig:
                unciphered = n2s(m)
                break
            c += pub_key.n
    else:
        if args.verbose:
            print "[*] Try weak key attack via factordb.com"
        try:
            pub_key.prime_factors()
            priv_key = PrivateKey(long(pub_key.p),
                                  long(pub_key.q),
                                  long(pub_key.e),
                                  long(pub_key.n))

            if args.uncipher is not None:
                unciphered = priv_key.decrypt(cipher)
        except FactorizationError:
            unciphered = None

    if unciphered is None and priv_key is None:
        if args.verbose:
            print "[*] Try Wiener's attack"

        # Wiener's attack
        wiener = WienerAttack(pub_key.n,
                              pub_key.e)
        if wiener.p is not None and wiener.q is not None:
            pub_key.p = wiener.p
            pub_key.q = wiener.q
            priv_key = PrivateKey(long(pub_key.p),
                                  long(pub_key.q),
                                  long(pub_key.e),
                                  long(pub_key.n))

            if args.uncipher is not None:
                unciphered = priv_key.decrypt(cipher)

    if unciphered is None and priv_key is None:
        if args.verbose:
            print "[*] Try Small q attack"

	# Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
	for prime in primes(100000):
	    if pub_key.n % prime == 0:
		pub_key.q = prime
		pub_key.p = pub_key.n / pub_key.q
		priv_key = PrivateKey(long(pub_key.p),
				  long(pub_key.q),
				  long(pub_key.e),
				  long(pub_key.n))

		if args.uncipher is not None:
			unciphered = priv_key.decrypt(cipher)
    try: 
	    if unciphered is None and priv_key is None and cipher is not None:	
		if args.verbose:
			print "[*] Try common factor attack"

		# Try an attack where the public key has a common factor with the ciphertext - sourcekris
		commonfactor = gcd(pub_key.n, s2n(cipher))
		
		if commonfactor > 1:
			pub_key.q = commonfactor
			pub_key.p = pub_key.n / pub_key.q
			priv_key = PrivateKey(long(pub_key.p),
				       long(pub_key.q),
				       long(pub_key.e),
				       long(pub_key.n))

			if args.uncipher is not None:
				unciphered = priv_key.decrypt(cipher)
    except NameError:
	# ciphertext wasnt loaded from cli
	pass

    if unciphered is None and priv_key is None:	
        if args.verbose:
		print "[*] Try fermat factorization due to close primes attack"

	# Try an attack where the primes are too close together from BKPCTF2016 - sourcekris
	with timeout(seconds=30):	
		pub_key.p, pub_key.q = fermat(pub_key.n)	

	if pub_key.q is not None:
		priv_key = PrivateKey(long(pub_key.p),
                               long(pub_key.q),
                               long(pub_key.e),
                               long(pub_key.n))

		if args.uncipher is not None:
			unciphered = priv_key.decrypt(cipher)

    if priv_key is not None and args.private:
        print priv_key

    if unciphered is not None and args.uncipher is not None:
        print "[+] Clear text : %s" % unciphered
    else:
        if args.uncipher is not None:
            print "[-] Sorry, cracking failed"
