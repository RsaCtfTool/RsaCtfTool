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
import requests
import re
import argparse


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
        except:
            # Ok, it's not nice to catch every exception, but
            # i'm bored right now
            print "[!] Error with factordb.com"

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

if __name__ == "__main__":
    """Main method (entrypoint)
    """
    parser = argparse.ArgumentParser(description='RSA CTF Tool')
    parser.add_argument('--publickey',
                        dest='public_key',
                        help='public key file',
                        required=True)
    parser.add_argument('--private',
                        dest='private',
                        help='display private key',
                        action='store_true')
    parser.add_argument('--uncipher',
                        dest='uncipher',
                        help='uncipher a file',
                        default=None)
    parser.add_argument('--verbose',
                        dest='verbose',
                        help='verbose mode (display n, e, p and q)',
                        action='store_true')

    args = parser.parse_args()

    if not args.private and not args.uncipher:
        print "Select between --private and --uncipher"
    else:
        # Load public key
        key = open(args.public_key, 'r').read()
        pub_key = PublicKey(key)
        pub_key.prime_factors()

        # If verbose, display components
        if args.verbose:
            print "n : %i" % pub_key.n
            print "e : %i" % pub_key.e
            print "p : %i" % pub_key.p
            print "q : %i" % pub_key.q

        # Try to factorise p & q from small key
        priv_key = PrivateKey(pub_key.p,
                              pub_key.q,
                              pub_key.e,
                              pub_key.n)

        # Display private key
        if args.private:
            print priv_key

        # Uncipher file content
        if args.uncipher is not None:
            cipher = open(args.uncipher, 'r').read().strip()
            print priv_key.decrypt(cipher)
