from __future__ import division


def factordb(n):
  try:
    from factordb.factordb import FactorDB
    if n < 2**128:
      return None
    f = FactorDB(n)
    f.connect()
    if f.get_status() in ['FF', 'CF']:
      return int(f.get_factor_list()[0])
  except ImportError:
    return None

__all__ = [factordb]
