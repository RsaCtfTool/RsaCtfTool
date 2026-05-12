# Attack Test Coverage

This document tracks which attacks have test coverage in `tests/test_attacks.py`.

## Summary

| Category | Total | With Tests | Without Tests |
|----------|-------|------------|---------------|
| Single Key | 56 | 17 | 39 |
| Multi Keys | 4 | 3 | 1 |
| **Total** | **60** | **20** | **40** |

---

## Single Key Attacks

- [ ] binary_polynomial_factoring.py
- [x] boneh_durfee.py (via wiener)
- [ ] brent.py
- [ ] carmichael.py
- [ ] classical_shor.py
- [ ] comfact_cn.py
- [ ] compositorial_pm1_gcd.py
- [x] cube_root.py
- [ ] dixon.py
- [x] ecm.py
- [ ] ecm2.py
- [ ] euler.py
- [ ] factor_2PN.py
- [x] factordb.py
- [ ] factorial_pm1_gcd.py
- [x] fermat.py
- [x] fermat_numbers_gcd.py
- [x] fibonacci_gcd.py
- [ ] hart.py
- [ ] highandlowbitsequal.py
- [ ] kraitchik.py
- [ ] lattice.py
- [ ] lehman.py
- [ ] lehmer.py
- [ ] londahl.py
- [ ] lucas_gcd.py
- [x] mersenne_pm1_gcd.py
- [ ] mersenne_primes.py
- [ ] multiple_base_inversion_gcd.py
- [ ] neca.py
- [ ] nonRSA.py
- [x] noveltyprimes.py
- [ ] nullattack.py
- [ ] partial_d.py
- [ ] partial_q.py
- [x] pastctfprimes.py
- [ ] pisano_period.py
- [ ] pollard_p_1.py
- [ ] pollard_rho.py
- [ ] pollard_strassen.py
- [x] primorial_pm1_gcd.py
- [ ] qicheng.py
- [ ] qs.py
- [ ] rapid7primes.py
- [x] roca.py
- [x] siqs.py
- [x] small_crt_exp.py
- [ ] smallfraction.py
- [x] smallq.py
- [ ] SQUFOF.py
- [ ] system_primes_gcd.py
- [x] wiener.py
- [ ] williams_pp1.py
- [ ] wolframalpha.py
- [ ] XYXZ.py
- [ ] z3_solver.py

---

## Multi Keys Attacks

- [x] common_factors.py
- [ ] common_modulus_related_message.py
- [x] hastads.py
- [x] same_n_huge_e.py

---

## Legend

- [x] = Has test
- [ ] = Missing test