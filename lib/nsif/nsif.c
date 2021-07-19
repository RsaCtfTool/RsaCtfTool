#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <gmp.h>

/* 
 * NSI Authors , Enrique Santos, Vicent Nos, Francisco Izquierdo
 * C++ Algo improvements, BanachTarskiVeli
 * Solution of banachtarskiveli to NSI/ RSA POISONING / Powe Modular factorization with base difference
 *
 * https://www.reddit.com/r/cryptography/comments/on10oc/factorization_challenge_rsa_poisoning_vs_others/
*/

void factor(mpz_t r, const mpz_t n, const int base, const size_t limit) {
        size_t logn = mpz_sizeinbase(n, base);
        mpz_t fexp,x;
        mpz_inits(fexp,x,NULL);
        mpz_ui_pow_ui(fexp, base, logn);

        size_t i;

        while(logn > 1) {
                mpz_set(x, fexp);
                for(i = 0; i < limit; i++) {
                        if(mpz_divisible_p(n,x)) {
                                mpz_set(r, x);
                                logn = 1;
                                break;
                        }

                        mpz_add_ui(x, x, 1);
                }
                logn--;
                mpz_tdiv_q_ui(fexp, fexp, base);
        }

        mpz_clears(fexp, x, NULL);
}

#define DEFAULT_BASE 3
#define DEFAULT_LIMIT 1000

int main(int argc, char* argv[])
{
        mpz_t n,r;
        mpz_init_set_str(n, argv[1], 10);
        mpz_init_set_ui(r, 0);

        factor(r, n, DEFAULT_BASE, DEFAULT_LIMIT);

        if(mpz_cmp_ui(r, 0) == 0) {
                printf("Could not find factor\n");
        } else {
                gmp_printf("Found factor:\n  %Zd\n", r);
        }
}


