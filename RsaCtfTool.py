#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
"""

import sys
import logging
import argparse
import urllib3
import tempfile
from glob import glob
from Crypto.PublicKey import RSA
from lib.rsa_attack import RSAAttack
from lib.rsalibnum import n2s, invmod
from lib.utils import get_numeric_value, print_results
from os.path import dirname, basename, isfile, join
from urllib3.exceptions import InsecureRequestWarning
from lib.customlogger import CustomFormatter, logger_levels
from lib.keys_wrapper import (
    generate_pq_from_n_and_p_or_q,
    generate_keys_from_p_q_e_n,
    PrivateKey,
)

# Remove insecure warning for factordb.com
urllib3.disable_warnings(InsecureRequestWarning)

# Change recursion limit for... you know, factorizing stuff...
sys.setrecursionlimit(5000)

if __name__ == "__main__":

    logger = logging.getLogger("global_logger")
    parser = argparse.ArgumentParser(description="RSA CTF Tool")
    parser.add_argument(
        "--publickey", help="public key file. You can use wildcards for multiple keys."
    )
    parser.add_argument(
        "--output", help="output file for results (privates keys, plaintext data)."
    )
    parser.add_argument(
        "--timeout", help="Timeout for long attacks.", default=60, type=int
    )
    parser.add_argument(
        "--createpub",
        help="Take n and e from cli and just print a public key then exit",
        action="store_true",
    )
    parser.add_argument(
        "--dumpkey",
        help="Just dump the RSA variables from a key - n,e,d,p,q",
        action="store_true",
    )
    parser.add_argument(
        "--ext",
        help="Extended dump of RSA private variables in --dumpkey mode - dp,dq,pinv,qinv).",
        action="store_true",
    )
    parser.add_argument("--uncipherfile", help="uncipher a file", default=None)
    parser.add_argument("--uncipher", help="uncipher a cipher", default=None)
    parser.add_argument(
        "--verbosity", help="verbose mode", choices=logger_levels.keys(), default="INFO"
    )
    parser.add_argument(
        "--private", help="Display private key if recovered", action="store_true"
    )
    parser.add_argument("--tests", help="Run tests on attacks", action="store_true")
    parser.add_argument(
        "--ecmdigits",
        type=int,
        help="Optionally an estimate as to how long one of the primes is for ECM method",
        default=None,
    )
    parser.add_argument("-n", help="Specify the modulus. format : int or 0xhex")
    parser.add_argument(
        "-p", help="Specify the first prime number. format : int or 0xhex"
    )
    parser.add_argument(
        "-q", help="Specify the second prime number. format : int or 0xhex"
    )
    parser.add_argument("-e", help="Specify the public exponent. format : int or 0xhex")
    parser.add_argument("--key", help="Specify the private key file.")
    parser.add_argument("--password", help="Private key password if needed.")

    # Dynamic load all attacks for choices in argparse
    attacks = glob(join(dirname(__file__), "attacks", "single_key", "*.py"))
    attacks += glob(join(dirname(__file__), "attacks", "multi_keys", "*.py"))
    attacks_filtered = [
        basename(f)[:-3] for f in attacks if isfile(f) and not f.endswith("__init__.py")
    ]
    attacks_list = [_ for _ in attacks_filtered if _ != "nullattack"] + ["all"]
    parser.add_argument(
        "--attack", help="Specify the attack modes.", default="all", nargs="+", choices=attacks_list
    )
    parser.add_argument(
        "--sendtofdb", help="Send results to factordb", action="store_true"
    )
    parser.add_argument(
        "--isconspicuous", help="conspicuous key check", action="store_true"
    )

    args = parser.parse_args()

    unciphers = []

    # Set logger level
    logging.basicConfig(
        level=logger_levels[args.verbosity],
    )
    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    logger = logging.getLogger("global_logger")
    logger.propagate = False
    logger.addHandler(ch)

    # If no arguments, diplay help and exit
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Add information
    if not args.private and not args.tests:
        logger.warning(
            "private argument is not set, the private key will not be displayed, even if recovered."
        )

    # Parse longs if exists
    if args.p is not None:
        args.p = get_numeric_value(args.p)

    if args.q is not None:
        args.q = get_numeric_value(args.q)

    if args.e is not None:
        args.e = get_numeric_value(args.e)

    # get n if we can
    if args.n is not None:
        args.n = get_numeric_value(args.n)
    elif args.p is not None and args.q is not None:
        args.n = args.p * args.q

    # if we have uncipher but no uncipherfile
    if args.uncipher is not None:
        uncipher_array = []
        for uncipher in args.uncipher.split(","):
            uncipher = get_numeric_value(uncipher)
            uncipher_array.append(n2s(uncipher))
        args.uncipher = uncipher_array

    # if we have uncipherfile
    if args.uncipherfile is not None:
        uncipher_array = []
        for uncipher in args.uncipherfile.split(","):
            try:
                with open(uncipher, "rb") as cipherfile_fd:
                    uncipher_array.append(cipherfile_fd.read())
            except OSError:
                logger.info("--uncipherfile : file not found or not readable.")
                exit(1)
        args.uncipher = uncipher_array

    # If we have a private key in input and uncipher in args (or uncipherfile)
    if args.key and args.uncipher:
        priv_key = PrivateKey(filename=args.key, password=args.password)
        for u in args.uncipher:
            unciphers.append(priv_key.decrypt(args.u))
        print_results(args, None, priv_key, unciphers)
        exit(0)

    # If we have n and one of p and q, calculated the other
    if args.n and (args.p or args.q):
        args.p, args.q = generate_pq_from_n_and_p_or_q(args.n, args.p, args.q)

    # Create pubkey if requested
    if args.createpub:
        pub_key, priv_key = generate_keys_from_p_q_e_n(args.p, args.q, args.e, args.n)
        print(pub_key.decode("utf-8"))
        exit(0)

    # Load keys
    tmpfile = None
    if args.publickey is None and args.e is not None and args.n is not None:
        tmpfile = tempfile.NamedTemporaryFile()
        with open(tmpfile.name, "wb") as tmpfd:
            tmpfd.write(RSA.construct((args.n, args.e)).publickey().exportKey())
        args.publickey = [tmpfile.name]

    elif args.publickey is not None:
        if "*" in args.publickey or "?" in args.publickey:
            pubkeyfilelist = glob(args.publickey)
            args.publickey = pubkeyfilelist
        elif "," in args.publickey:
            args.publickey = args.publickey.split(",")
        else:
            args.publickey = [args.publickey]

    # If we already have all informations
    if (
        args.p is not None
        and args.q is not None
        and args.e is not None
        and args.n is not None
    ):
        try:
            pub_key, priv_key = generate_keys_from_p_q_e_n(
                args.p, args.q, args.e, args.n
            )
        except ValueError:
            logger.error(
                "Looks like the values for generating key are not ok... (no invmod)"
            )
            exit(1)

        if args.createpub:
            print(pub_key)

        if args.uncipher is not None:
            for u in args.uncipher:
                if priv_key is not None:
                    unciphers.append(priv_key.decrypt(args.uncipher))
                else:
                    logger.error(
                        "Looks like the values for generating key are not ok... (no invmod)"
                    )
                    exit(1)
        print_results(args, args.publickey[0], priv_key, unciphers)
        exit(0)

    # Dump public key informations
    if (
        args.dumpkey
        and not args.private
        and args.uncipher is None
        and args.uncipherfile is None
        and args.publickey is not None
    ):
        for publickey in args.publickey:
            logger.info("Details for %s:" % publickey)
            with open(publickey, "rb") as key_data_fd:
                key = RSA.importKey(key_data_fd.read())
                print("n: " + str(key.n))
                print("e: " + str(key.e))
        exit(0)

    # if dumpkey mode dump the key components then quit
    if args.key is not None and args.dumpkey:
        key_data = open(args.key, "rb").read()
        key = RSA.importKey(key_data)
        print("n: " + str(key.n))
        print("e: " + str(key.e))
        if key.has_private():
            print("d: " + str(key.d))
            print("p: " + str(key.p))
            print("q: " + str(key.q))
            if args.ext:
                dp = key.d % (key.p - 1)
                dq = key.d % (key.q - 1)
                pinv = invmod(key.p, key.q)
                qinv = invmod(key.q, key.p)
                print("dp: " + str(dp))
                print("dq: " + str(dq))
                print("pinv: " + str(pinv))
                print("qinv: " + str(qinv))

        exit(0)

    if args.key is not None and args.isconspicuous:
        with open(args.key, "rb") as key_fp:
            key_data = key_fp.read()
            key = RSA.importKey(key_data)
            try:
                pub_key, priv_key = generate_keys_from_p_q_e_n(
                    args.p, args.q, args.e, args.n
                )
            except ValueError:
                logger.error(
                    "Looks like the values for generating key are not ok... (no invmod)"
                )
                exit(1)
            if priv_key.is_conspicuous() == True:
                exit(-1)
            else:
                exit(0)

    # Run attacks
    found = False
    attackobj = RSAAttack(args)

    # Run tests
    if args.publickey is None and args.tests:
        tmpfile = tempfile.NamedTemporaryFile()
        with open(tmpfile.name, "wb") as tmpfd:
            tmpfd.write(RSA.construct((15, 3)).publickey().exportKey())
            attackobj.attack_single_key(tmpfile.name, attacks_list, test=True)

    # Attack multiple keys
    if len(args.publickey) > 1:
        found = attackobj.attack_multiple_keys(args.publickey, attacks_list)

    # Attack key
    if not found:
        for publickey in args.publickey:
            attackobj.implemented_attacks = []
            logger.info("\n[*] Testing key %s." % publickey)
            attackobj.attack_single_key(publickey, attacks_list)
            attackobj.unciphered = []
