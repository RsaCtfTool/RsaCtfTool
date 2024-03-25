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

import os
import sys
import logging
import argparse
import urllib3
import tempfile
from glob import glob
from lib.crypto_wrapper import RSA
from lib.rsa_attack import RSAAttack
from lib.number_theory import invmod, factor_ned
from lib.utils import get_numeric_value, print_results, get_base64_value, n2s
from os.path import dirname, basename, isfile, join
from urllib3.exceptions import InsecureRequestWarning
from lib.customlogger import CustomFormatter, logger_levels
from lib.keys_wrapper import (
    generate_pq_from_n_and_p_or_q,
    generate_keys_from_p_q_e_n,
    PrivateKey,
)
from lib.idrsa_pub_disector import disect_idrsa_pub
from lib.is_roca_test import is_roca_vulnerable

# Remove insecure warning for factordb.com
urllib3.disable_warnings(InsecureRequestWarning)

# Change recursion limit for... you know, factorizing stuff...
sys.setrecursionlimit(5000)


def banner():
    cEND = "\033[0m"
    cRED = "\033[1;31m"
    return (
        r"""
__________               R_______________________________E __                .__
\______   \ ___________  R\_   ___ \__    ___/\_   _____/E/  |_  ____   ____ |  |
 |       _//  ___/\__  \ R/    \  \/ |    |    |    __)E \   __\/  _ \ /  _ \|  |
 |    |   \\\___ \  / __ \R\     \____|    |    |     \E   |  | (  <_> |  <_> )  |__
 |____|_  /____  >(____  /R\______  /|____|    \___  /E   |__|  \____/ \____/|____/
        \/     \/      \/        R\/E               R\/E

""".replace(
            "R", cRED
        ).replace(
            "E", cEND
        )
        + """
Disclaimer: this tool is meant for educational purposes, for those doing CTF's first try:

Learning the basis of RSA math, undrestand number theory, modular arithmetric, integer factorization, fundamental theorem of arithmetic.
Read the code in this repo to see what and how it does and how to improve it, send PR's.
Avoid copy-paste-run and at last run this tool (knowking the math is more valuable than knowking how to run this tool).

"""
    )


def parse_args():
    parser = argparse.ArgumentParser(description="RSA CTF Tool")

    parser.add_argument(
        "--publickey", help="public key file. You can use wildcards for multiple keys."
    )
    parser.add_argument(
        "--output", help="output file for results (privates keys, plaintext data)."
    )
    parser.add_argument(
        "--timeout",
        help="Timeout for long attacks in seconds. default is 60s min: MIN_INT in C, max: MAX_INT in C, values < 1 have the same effect as MAX_INT",
        default=60,
        type=int,
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
    parser.add_argument(
        "--decryptfile",
        help="decrypt a file, using commas to separate multiple paths",
        default=None,
    )
    parser.add_argument(
        "--decrypt",
        help="decrypt a cipher, using commas to separate multiple ciphers",
        default=None,
    )
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
    parser.add_argument(
        "-e",
        help="Specify the public exponent, using commas to separate multiple exponents. format : int or 0xhex",
    )
    parser.add_argument(
        "-d",
        help="Specify the private exponent. Format : int or 0xhex",
    )
    parser.add_argument("--key", help="Specify the private key file.")
    parser.add_argument("--password", help="Private key password if needed.")

    # If no arguments, display help and exit
    if len(sys.argv) == 1:
        print(banner())
        parser.print_help()
        sys.exit(1)

    # Dynamic load all attacks for choices in argparse
    attacks = glob(
        join(dirname(os.path.realpath(__file__)), "attacks", "single_key", "*.py")
    )
    attacks += glob(
        join(dirname(os.path.realpath(__file__)), "attacks", "multi_keys", "*.py")
    )

    attacks_filtered = [
        basename(f)[:-3] for f in attacks if isfile(f) and not f.endswith("__init__.py")
    ]
    attacks_list = [_ for _ in attacks_filtered if _ != "nullattack"] + ["all"]
    parser.add_argument(
        "--attack",
        help="Specify the attack modes.",
        default="all",
        nargs="+",
        choices=attacks_list,
    )
    parser.add_argument(
        "--sendtofdb", help="Send results to factordb", action="store_true"
    )
    parser.add_argument(
        "--isconspicuous", help="conspicuous key check", action="store_true"
    )
    parser.add_argument(
        "--isroca", help="Check if given key is roca", action="store_true"
    )

    parser.add_argument(
        "--convert_idrsa_pub", help="Convert idrsa.pub to pem", action="store_true"
    )
    parser.add_argument(
        "--check_publickey",
        help="Check publickey if modulus is well formed before attack",
        action="store_true",
    )

    parser.add_argument(
        "--partial",
        help="work with partial priate keys",
        action="store_true",
    )

    parser.add_argument(
        "--cleanup",
        help="cleanup *.pub files after finish",
        action="store_true",
    )

    parser.add_argument(
        "--withtraceback",
        help="show tracebacks",
        action="store_true",
    )

    parser.add_argument(
        "--show_modulus",
        help="show tracebacks",
        action="store_true",
    )

    args = parser.parse_args()
    args.attacks_list = attacks_list
    return args


def run_conspicuous_check(args, logger):
    try:
        pub_key, priv_key = generate_keys_from_p_q_e_n(args.p, args.q, args.e, args.n)
    except ValueError:
        logger.error(
            "Looks like the values for generating key are not ok... (no invmod)"
        )
        return False
    c = priv_key.is_conspicuous()
    if c:
        logger.warning("[!] Key is conspicuous...")
    return c


def run_attacks(args, logger):
    # Run attacks
    found = False
    attackobj = RSAAttack(args)
    selected_attacks = args.attacks_list

    # Run tests
    if args.publickey is None and args.tests:
        if args.attack is not None:
            if "," not in args.attack:
                selected_attacks = args.attack
        if "all" in selected_attacks:
            selected_attacks = args.attacks_list
        logger.info("Testing attacks: %d" % len(selected_attacks))

        tmpfile = tempfile.NamedTemporaryFile()
        with open(tmpfile.name, "wb") as tmpfd:
            tmpfd.write(RSA.construct((35, 3)).publickey().exportKey())
            attackobj.attack_single_key(tmpfile.name, selected_attacks, test=True)
            sys.exit(0)

    # Attack multiple keys
    if args.publickey is not None and len(args.publickey) > 1:
        found = attackobj.attack_multiple_keys(args.publickey, selected_attacks)

    # Attack key
    if args.publickey is not None:
        for publickey in args.publickey:
            attackobj.implemented_attacks = []
            attackobj.decrypted = []
            logger.info("\n[*] Testing key %s." % publickey)
            attackobj.attack_single_key(publickey, selected_attacks)
    if args.publickey is None:
        if args.partial:
            priv_key = PrivateKey(filename=args.key, password=None)
            attackobj.attack_single_key(priv_key, selected_attacks)
        else:
            logger.error("No key specified")
        if args.n is not None:
            # FIXME
            publickey, _privkey = generate_keys_from_p_q_e_n(
                args.p, args.q, args.e, args.n
            )
            attackobj.attack_single_key(publickey, selected_attacks)
    return args


def convert_idrsa_pub(args, logger):
    # for publickey in args.publickey:
    publickeys = glob(args.publickey)
    for publickey in publickeys:
        logger.info(f"Converting {publickey}: to pem...")
        with open(publickey, "r") as key_data_fd:
            for line in key_data_fd:
                n, e = disect_idrsa_pub(line.rstrip())
                if n and e:
                    pub_key, _ = generate_keys_from_p_q_e_n(None, None, e, n)
                    if pub_key:
                        logger.info(pub_key.decode("utf-8"))
                    else:
                        logger.error("Error generating keys from n and e values.")


def check_is_roca(args, logger):
    """
    Checks the given list of public key files for the ROCA vulnerability.

    Args:
        args (Namespace): Command line arguments or configuration settings.
        logger: Logger instance for logging messages.

    Returns:
        bool: True if any of the public keys are vulnerable, False otherwise.
    """
    vuln = False
    pubkeyfilelist = glob(args.publickey)
    for publickey in pubkeyfilelist:
        logger.info(f"[-] Details for {publickey}:")
        with open(publickey, "rb") as key_data_fd:
            try:
                key = RSA.importKey(key_data_fd.read())
            except Exception as e:
                key = None
                logger.error(f"[!] Error file format: {publickey}")
            if key is not None:
                if is_roca_vulnerable(key.n):
                    vuln = True
                    logger.warning(f"[!] Public key {publickey}: is roca!!!")
                else:
                    logger.info(f"[-] Public key {publickey}: is not roca, you are safe")
    return vuln


def load_keys(args, logger):
    tmpfile = None
    args.publickey = []
    for e in args.e if isinstance(args.e, list) else [args.e]:
        tmpfile = tempfile.NamedTemporaryFile(delete=False)
        with open(tmpfile.name, "wb") as tmpfd:
            tmpfd.write(
                RSA.construct((args.n, e)).publickey().exportKey(),
            )
        args.publickey.append(tmpfile.name)
    return args


def dump_key_parameters(args):
    key_data = open(args.key, "rb").read()
    key = RSA.importKey(key_data)
    print(f"n: {str(key.n)}")
    print(f"e: {str(key.e)}")
    if key.has_private():
        print(f"d: {str(key.d)}")
        print(f"p: {str(key.p)}")
        print(f"q: {str(key.q)}")
        if args.ext:
            dp = key.d % (key.p - 1)
            dq = key.d % (key.q - 1)
            pinv = invmod(key.p, key.q)
            qinv = invmod(key.q, key.p)
            print(f"dp: {str(dp)}")
            print(f"dq: {str(dq)}")
            print(f"pinv: {str(pinv)}")
            print(f"qinv: {str(qinv)}")


def decrypt_file(args, logger):
    """
    Decrypts files specified in args.decryptfile using the provided private key, or prepares files for decryption with a public key.
    Note: Currently, decryption with a private key may not work correctly.

    Args:
        args (Namespace): Command-line arguments.
        logger (Logger): Logger object for logging messages.

    Returns:
        bool: True if decryption is successful with a private key, or if files are prepared for decryption with a public key; False otherwise.
    """
    decrypt_array = []
    for decrypt in args.decryptfile.split(","):
        try:
            with open(decrypt, "rb") as cipherfile_fd:
                decrypt_value = get_base64_value(cipherfile_fd.read())
                decrypt_array.append(decrypt_value)
        except OSError:
            logger.info("--decryptfile : file not found or not readable.")
            return False
    args.decrypt = decrypt_array

    # Check if a private key is provided and there's something to decrypt
    if args.key and args.decrypt:
        priv_key = PrivateKey(filename=args.key, password=args.password)
        decrypts = priv_key.decrypt(args.decrypt)
        print_results(args, None, priv_key, decrypts)
        return True

    # Check if a public key is provided
    if args.publickey:
        return True

    # No private key or public key provided
    logger.error("Private key or public key and decrypted data are required.")
    return False


def pubkey_detail(args, logger):
    for publickey in args.publickey:
        logger.info(f"Details for {publickey}:")
        with open(publickey, "rb") as key_data_fd:
            key = RSA.importKey(key_data_fd.read())
            print(f"n: {str(key.n)}")
            print(f"e: {str(key.e)}")


def cleanup(args):
    if args.publickey is not None:
        for pub in args.publickey:
            try:
                if "tmp" in pub and "tmp/" not in pub:
                    os.remove(pub)
            except:
                continue


def main():
    logger = logging.getLogger("global_logger")
    args = parse_args()

    decrypts = []

    # Set logger level
    logging.basicConfig(
        level=logger_levels[args.verbosity],
    )
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(CustomFormatter())
    logger = logging.getLogger("global_logger")
    logger.propagate = False
    logger.addHandler(ch)

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

    if args.d is not None:
        args.d = get_numeric_value(args.d)

    if args.e is not None:
        e_array = []
        for e in args.e.split(","):
            e_int = get_numeric_value(e)
            e_array.append(e_int)
        args.e = e_array if len(e_array) > 1 else e_array[0]
    elif args.n is not None:
        args.e = 65537

    # get n if we can
    if args.n is not None:
        args.n = get_numeric_value(args.n)
    elif args.p is not None and args.q is not None:
        args.n = args.p * args.q

    if args.n is not None and (args.p is not None or args.q is not None):
        logger.warning(
            "[!] It seems you already provided one of the prime factors, nothing to do here..."
        )

    # get p and q from n, e and d
    if args.n is not None and args.e is not None and args.d is not None and args.p is None and args.q is None:
        pq = factor_ned(args.n, args.e, args.d)
        if pq is not None:
            args.p, args.q = pq
        else:
            logger.warning("[!] Impossible to recover p and q from d")

    # if we have decrypt but no decryptfile
    if args.decrypt is not None:
        decrypt_array = []
        for decrypt in args.decrypt.split(","):
            try:
                decrypt = get_numeric_value(decrypt)
            except:
                decrypt = get_base64_value(decrypt)
            decrypt_array.append(n2s(decrypt))
        args.decrypt = decrypt_array

    # if we have decryptfile
    if args.decryptfile is not None:
        if not decrypt_file(args, logger):
            sys.exit(-1)

    # If we have n and one of p and q, calculated the other
    if args.n and (args.p or args.q):
        args.p, args.q = generate_pq_from_n_and_p_or_q(args.n, args.p, args.q)

    # convert a idrsa.pub file to a pem format
    if args.convert_idrsa_pub:
        convert_idrsa_pub(args, logger)
        sys.exit(0)

    if args.isroca:
        check_is_roca(args, logger)
        sys.exit(0)

    # Create pubkey if requested
    if args.createpub:
        pub_key, priv_key = generate_keys_from_p_q_e_n(args.p, args.q, args.e, args.n)
        print(pub_key.decode("utf-8"))
        sys.exit(0)

    # Load keys
    if args.publickey is None and args.e is not None and args.n is not None:
        args = load_keys(args, logger)

    elif args.publickey is not None:
        if "*" in args.publickey or "?" in args.publickey:
            pubkeyfilelist = glob(args.publickey)
            args.publickey = pubkeyfilelist

        elif "," in args.publickey:
            args.publickey = args.publickey.split(",")
        else:
            args.publickey = [args.publickey]

    print(args.publickey)

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
            sys.exit(1)

        if args.createpub:
            pub_key, priv_key = generate_keys_from_p_q_e_n(
                args.p, args.q, args.e, args.n
            )
            print(pub_key.decode("utf-8"))

        if args.decrypt is not None:
            for u in args.decrypt:
                if priv_key is not None:
                    decrypts.append(priv_key.decrypt(args.decrypt))
                else:
                    logger.error(
                        "Looks like the values for generating key are not ok... (no invmod)"
                    )
                    sys.exit(1)
        print_results(args, args.publickey[0], priv_key, decrypts)
        sys.exit(0)

    # Dump public key informations
    if (
        args.dumpkey
        and not args.private
        and args.decrypt is None
        and args.decryptfile is None
        and args.publickey is not None
    ):
        pubkey_detail(args, logger)
        sys.exit(0)

    # if dumpkey mode dump the key components then quit
    if args.key is not None and args.dumpkey:
        dump_key_parameters(args)
        sys.exit(0)

    if args.key is not None and args.isconspicuous:
        if run_conspicuous_check(args, logger):
            sys.exit(-1)
        else:
            sys.exit(0)

    args = run_attacks(args, logger)

    # Finish and cleanup
    if args.cleanup:
        cleanup(args)


if __name__ == "__main__":
    main()
