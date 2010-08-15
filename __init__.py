#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
#
# Copyright 2010 HH
#
# All Rights Reserved
# hh@hhmds.com 2010

"""Asynchronous Encryption Keys
"""

__authors__ = [
  '"Andrew D. Yates" <andrew.yates@hhmds.com>',
]


from google.appengine.ext import db

import integers


class RSAKey(db.Model):
  
  """Asymmetric encryption and signature key.

  Components stored as < 500 bytestrings. Compute integers from bytestrings
  for cryptography with self.refresh_values().

  Assume "The Internet" is sufficient RSA blinding.
  
  To Do:
  - key generation
  - PEM export
  - private blinding
  - add p, q, dP, dQ, qInv
  - Chinese Remainder Theorem computation

  Attributes:
    e: int of `self.exponent` bytes
    n: int of `self.modulus` bytes
    d: int of `self.decryption` exponent bytes
    ...
  """
  
  exponent = db.ByteStringProperty(required=True)
  modulus = db.ByteStringProperty(required=True)
  decrypt = db.ByteStringProperty()

  def __init__(self, *args, **kwds):
    """Get integers from bytestrings saved in data"""
    super(RSAKey, self).__init__(*args, **kwds)
    self.refresh()
  
  @property
  def size(self):
    return len(self.modulus)
  
  def refresh(self):
    """Set cached integers from corresponding bytestrings.
    """
    self.e = integers.get_int(self.exponent)
    self.n = integers.get_int(self.modulus)
    self.d = integers.get_int(self.decrypt)
    
  def private(self, data):
    """Private Key Transform: decrypt, sign
    
    Args:
      data: str of bytestring to transform
    Returns:
      str: of bytestring of transformed `data`
    Raises:
      ValueError, AttributeError
    """
    c = integers.bytes_to_int(data)
    if self.n <= c:
      raise ValueError, "Data too long for key size"
    if not self.d:
      raise AttributeError, "No private component"
    m = pow(c, self.d, self.n)
    return integers.int_to_bytes(m)

  def public(self, data):
    """Public Key Transform: encrypt, verify
    
    Args:
      data: str of bytestring to transform
    Returns:
      str: of bytestring of transformed `data`
    Raises:
      ValueError
    """
    m = integers.bytes_to_int(data)
    if self.n <= m:
      raise ValueError, "Data too long for key size"
    c = pow(m, self.e, self.n)
    return integers.int_to_bytes(c)
    
  def generate(self, size=128):
    """Generate a new RSA public / private key pair
    
    Args:
      size: int of bytes in modulus (default 128)
    """
    self.p = Prime(size/2)
    self.q = Prime(size/2)
    self.n = self.p * self.q
    self.e = 65537
    self.d = unmod(self.e, lcm(self.p-1, self.q-1))
    self.dP = self.d % (self.p-1)
    self.dQ = self.d % (self.q-1)
    self.qInv = unmod(self.q, self.p)
