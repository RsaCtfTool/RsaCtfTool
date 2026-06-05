# Attack Required Binaries
Some attack techniques implemented in RsaCtfTool require external binaries or libraries to execute successfully. If these dependencies are missing, the tool may skip those specific attacks or output a warning during the test phase. You can install most of these additional Python dependencies using the `optional-requirements.txt` file provided in the repository root (`pip install -r optional-requirements.txt`), while system binaries like `yafu` or `neca` must be compiled or installed manually on your environment.

## Dependency Summary
* **SageMath (`sage`) Dependent (9 Attacks):** `binary_polynomial_factoring`, `boneh_durfee`, `ecm`, `ecm2`, `neca`, `qicheng`, `roca`, `small_crt_exp`, `smallfraction`
* **Yafu (`yafu`) Dependent (1 Attack):** `siqs`
* **Neca (`neca`) Dependent (1 Attacks):** `neca`
* **WolframAlpha (`wolframalpha`) Dependent (1 Attack):** `wolframalpha`
* **No External Dependencies (48 Attacks):** All other remaining attack techniques

## Lists

| Attack | Required Binaries |
| :--- | :--- |
| `binary_polynomial_factoring.py` | **`sage`** |
| `boneh_durfee.py` | **`sage`** |
| `brent.py` | *None* |
| `carmichael.py` | *None* |
| `classical_shor.py` | *None* |
| `comfact_cn.py` | *None* |
| `common_factors.py` | *None* |
| `common_modulus_related_message.py` | *None* |
| `compositorial_pm1_gcd.py` | *None* |
| `cube_root.py` | *None* |
| `dixon.py` | *None* |
| `ecm.py` | **`sage`** |
| `ecm2.py` | **`sage`** |
| `euler.py` | *None* |
| `factor_2PN.py` | *None* |
| `factordb.py` | *None* |
| `factorial_pm1_gcd.py` | *None* |
| `fermat.py` | *None* |
| `fermat_numbers_gcd.py` | *None* |
| `fibonacci_gcd.py` | *None* |
| `hart.py` | *None* |
| `hastads.py` | *None* |
| `highandlowbitsequal.py` | *None* |
| `kraitchik.py` | *None* |
| `lattice.py` | *None* |
| `lehman.py` | *None* |
| `lehmer.py` | *None* |
| `londahl.py` | *None* |
| `lucas_gcd.py` | *None* |
| `mersenne_pm1_gcd.py` | *None* |
| `mersenne_primes.py` | *None* |
| `multiple_base_inversion_gcd.py` | *None* |
| `neca.py` | **`sage`**, **`neca`** |
| `nonRSA.py` | *None* |
| `noveltyprimes.py` | *None* |
| `partial_d.py` | *None* |
| `partial_q.py` | *None* |
| `pastctfprimes.py` | *None* |
| `pisano_period.py` | *None* |
| `pollard_p_1.py` | *None* |
| `pollard_rho.py` | *None* |
| `pollard_strassen.py` | *None* |
| `primorial_pm1_gcd.py` | *None* |
| `qicheng.py` | **`sage`** |
| `qs.py` | *None* |
| `rapid7primes.py` | *None* |
| `roca.py` | **`sage`** |
| `same_n_huge_e.py` | *None* |
| `siqs.py` | **`yafu`** |
| `small_crt_exp.py` | **`sage`** |
| `smallfraction.py` | **`sage`** |
| `smallq.py` | *None* |
| `SQUFOF.py` | *None* |
| `system_primes_gcd.py` | *None* |
| `wiener.py` | *None* |
| `williams_pp1.py` | *None* |
| `wolframalpha.py` | **`wolframalpha`** |
| `XYXZ.py` | *None* |
| `z3_solver.py` | *None* |
