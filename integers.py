#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2010 Andrew D. Yates
# All Rights Reserved
"""Bytes to Integer Functions.

`int` types may be cast as `long`
"""
__authors__ = ['"Andrew D. Yates" <andrew.yates@hhmds.com>']


def bytes_to_int(s):
  """Return converted bytestring to integer.

  Args:
    s: str of bytes
  Returns:
    int: numeric interpreation of binary string `s`
  """
  # int type casts may return a long type
  return int(s.encode('hex'), 16)


def int_to_bytes(num):
  """Return converted integer to bytestring.

  Note: string encoding is faster than divmod(num, 256) in Python.

  Args:
    num: integer, non-negative
  Returns:
    str: bytestring of binary data to represent `num`
  Raises:
    ValueError: `num` is not a non-negative integer
  """
  if not is_natural(num, include_zero=True):
    raise ValueError("%s is not a non-negative integer.")
  hexed = "%x" % num
  # align hexademical string to byte boundaries
  if len(hexed) % 2 == 1:
    hexed = '0%s' % hexed
  return hexed.decode('hex')

  
def is_natural(value, include_zero=False):
  """Return if value is effectively a natural integer in Python.
  
  Returns:
    bool: is value a natural number?
  """
  return all((
    isinstance(value, (int, long)),
    value >= 0,
    not (value == 0 and not include_zero),
  ))


def get_int(s):
  """Get integer from bytestring or None.
  
  Args:
    s: str of bytestring
  Returns:
    int: of `s` if representation exists, else None
  """
  if s == None or s == '':
    return None
  else:
    return bytes_to_int(s)


def gcd(n, m):
  """Return the greatest common divisor of two natural numbers.
  
  Args:
    n: int > 0
    m: int > 0
  Returns:
    int: of greatest common divisor of `n` and `m`
  """
  x, y, r = solve_gcd_euclidean(n, m)
  return r
 

def lcm(n, m):
  """Return the least common multiple of two natural numbers.
  
  Args:
    n: int > 0
    m: int > 0
  Returns:
    int: least common multiple of `n` and `m`
  """
  return n * m // gcd(n, m)


def solve_gcd_euclidean(n, m):
  """Return solution to extended euclidean algorithm.

  See: http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

  Args:
    n: int > 0
    m: int > 0
  Returns:
    (int, int, int): (x, y, gcd(a,b)) for "x*n + y*m = gcd(n, m)"
  """
  x, xx = 1, 0
  y, yy = 0, 1
  r, rr = n, m
  
  while not rr == 0:
    div, mod = divmod(r, rr)
    r, rr = rr, mod
    x, xx = xx, x - xx * div
    y, yy = yy, y - yy * div

  gcd = r
  return x, y, gcd


def mmi(n, m):
  """Return Modular Multiplicative Inverse for n modulus m.

  Args:
    n: int > 1, coprime to `m`
    m: int > 1, coprime to `n`
  Returns:
    int: x > 0 for "x*n |= 1 mod(m)"
  Raises:
    ValueError: no solution exists
  """
  x, y, gcd = solve_gcd_euclidean(n, m)
  
  if not gcd == 1 or x == 0:
    raise ValueError("No solution for %d and %d." % (n, m))

  return (x + m) % m

