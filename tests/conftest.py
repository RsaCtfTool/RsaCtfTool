import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "network: marks tests requiring network access")
    config.addinivalue_line(
        "markers", "attack: marks integration tests for specific attacks"
    )


@pytest.fixture
def repo_root():
    return Path(__file__).parent.parent


@pytest.fixture
def examples_dir(repo_root):
    return repo_root / "examples"


@pytest.fixture
def small_rsa_key():
    p = 61
    q = 53
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return {"p": p, "q": q, "n": n, "e": e, "d": d, "phi": phi}


@pytest.fixture
def known_primes():
    return [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]


@pytest.fixture
def composite_numbers(known_primes):
    return [p * q for p, q in zip(known_primes[:5], known_primes[5:10])]


@pytest.fixture
def example_pub_files(examples_dir):
    if not examples_dir.exists():
        pytest.skip("examples directory not found")
    return list(examples_dir.glob("*.pub"))


@pytest.fixture
def example_cipher_files(examples_dir):
    if not examples_dir.exists():
        pytest.skip("examples directory not found")
    return list(examples_dir.glob("*.cipher"))


@pytest.fixture
def weak_public_key_path(examples_dir):
    return str(examples_dir / "weak_public.pub")


@pytest.fixture
def wiener_key_path(examples_dir):
    return str(examples_dir / "wiener.pub")


@pytest.fixture
def factordb_key_path(examples_dir):
    return str(examples_dir / "factordb_parse.pub")
