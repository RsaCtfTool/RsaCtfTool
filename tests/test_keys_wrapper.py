#!/usr/bin/env python3

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from RsaCtfTool.lib.keys_wrapper import (
    PublicKey,
    PrivateKey,
    generate_pq_from_n_and_p_or_q,
    generate_keys_from_p_q_e_n,
)
from RsaCtfTool.lib.number_theory import invmod


class TestPublicKey:
    def test_public_key_from_pem(self, weak_public_key_path):
        with open(weak_public_key_path, "r") as f:
            key_content = f.read()
        pub_key = PublicKey(key_content, filename=weak_public_key_path)
        assert pub_key.n is not None
        assert pub_key.e is not None
        assert "BEGIN PUBLIC KEY" in str(pub_key)

    def test_public_key_attributes(self, weak_public_key_path):
        with open(weak_public_key_path, "r") as f:
            key_content = f.read()
        pub_key = PublicKey(key_content)
        assert isinstance(pub_key.n, int)
        assert isinstance(pub_key.e, int)
        assert pub_key.n > 0
        assert pub_key.e > 0

    def test_public_key_invalid_format(self):
        with pytest.raises(Exception):
            PublicKey("-----BEGIN NOT A KEY-----")

    def test_public_key_str_representation(self, weak_public_key_path):
        with open(weak_public_key_path, "r") as f:
            key_content = f.read()
        pub_key = PublicKey(key_content)
        key_str = str(pub_key)
        assert "BEGIN PUBLIC KEY" in key_str
        assert "END PUBLIC KEY" in key_str


class TestPrivateKey:
    def test_private_key_from_p_q_e(self):
        p = 61
        q = 53
        n = p * q
        e = 17
        priv_key = PrivateKey(p=p, q=q, e=e, n=n)
        assert priv_key.p == p
        assert priv_key.q == q
        assert priv_key.e == e
        assert priv_key.n == n
        assert priv_key.d is not None

    def test_private_key_str_returns_str(self):
        p = 61
        q = 53
        n = p * q
        e = 17
        priv_key = PrivateKey(p=p, q=q, e=e, n=n)
        result = str(priv_key)
        assert isinstance(result, str)

    def test_private_key_str_nonempty_for_valid_key(self):
        p = 61
        q = 53
        n = p * q
        e = 17
        priv_key = PrivateKey(p=p, q=q, e=e, n=n)
        pem = str(priv_key)
        assert "BEGIN" in pem or len(pem) > 0

    def test_private_key_n_eq_p_squared(self):
        p = 1000000007
        n = p * p
        e = 65537
        phi = (p - 1) * p
        d = invmod(e, phi)
        priv_key = PrivateKey(n=n, e=e, d=d)
        result = str(priv_key)
        assert isinstance(result, str)

    def test_private_key_from_n_e_d(self):
        p = 61
        q = 53
        n = p * q
        e = 17
        phi = (p - 1) * (q - 1)
        d = invmod(e, phi)
        priv_key = PrivateKey(n=n, e=e, d=d)
        assert priv_key.n == n
        assert priv_key.e == e
        assert priv_key.d == d

    def test_private_key_d_computed_from_p_q_e(self):
        p = 61
        q = 53
        e = 65537
        n = p * q
        priv_key = PrivateKey(p=p, q=q, e=e, n=n)
        assert priv_key.d is not None
        assert (priv_key.d * e) % ((p - 1) * (q - 1)) == 1


class TestGeneratePQ:
    def test_generate_pq_from_n_and_q(self):
        p = 1009
        q = 1013
        n = p * q
        result_p, result_q = generate_pq_from_n_and_p_or_q(n, q=q)
        assert result_p == p
        assert result_q == q

    def test_generate_pq_from_n_and_p(self):
        p = 1009
        q = 1013
        n = p * q
        result_p, result_q = generate_pq_from_n_and_p_or_q(n, p=p)
        assert result_p == p
        assert result_q == q


class TestGenerateKeysFromPQE:
    def test_generate_keys_valid(self):
        p = 61
        q = 53
        e = 17
        n = p * q
        pub_key, priv_key = generate_keys_from_p_q_e_n(p, q, e, n)
        assert pub_key is not None
        assert priv_key is not None
        assert b"BEGIN PUBLIC KEY" in pub_key

    def test_generate_keys_pem_format(self):
        p = 61
        q = 53
        e = 17
        n = p * q
        pub_key, _ = generate_keys_from_p_q_e_n(p, q, e, n)
        assert "BEGIN PUBLIC KEY" in pub_key.decode()


class TestPrivateKeyDecrypt:
    def test_decrypt_raw_rsa(self):
        p = 61
        q = 53
        e = 17
        n = p * q
        priv_key = PrivateKey(p=p, q=q, e=e, n=n)
        plaintext_int = 42
        from RsaCtfTool.lib.number_theory import powmod

        cipher_int = powmod(plaintext_int, e, n)
        cipher_bytes = cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, "big")
        decrypted = priv_key.decrypt([cipher_bytes])
        assert len(decrypted) > 0

    def test_decrypt_non_list_input(self):
        p = 61
        q = 53
        e = 17
        n = p * q
        priv_key = PrivateKey(p=p, q=q, e=e, n=n)
        cipher_bytes = b"\x00" * 10
        decrypted = priv_key.decrypt(cipher_bytes)
        assert isinstance(decrypted, list)
