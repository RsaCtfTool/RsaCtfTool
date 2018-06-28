from __future__ import division

def fermat(n):
    from _primefac._arith import isqrt
    x = isqrt(n) + 1
    y = isqrt(x**2 - n)
    while True:
        w = x**2 - n - y**2
        if w == 0:
            break
        if w > 0:
            y += 1
        else:
            x += 1
    return x+y

__all__ = [fermat]
