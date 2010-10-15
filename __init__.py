#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2010 Andrew D. Yates
# All Rights Reserved
"""RSA Asynchronous Encryption Key for Google App Engine datastore.
"""

from google.appengine.ext import db

import integers


EXP = 65537


class LongProperty(db.Property):
  """Arbitrarily long integer stored as a bytestring."""
  data_type = long

  def get_value_for_datastore(self, model_instance):
    s = super(LongProperty, self).get_value_for_datastore(model_instance)
    return integers.int_to_bytes(s)

  def make_value_from_datastore(self, value):
    if value is None:
      return None
    return integers.bytes_to_int(value)


class RSAKey(db.Model):
  """RSA encryption and signature key as a datastore model.

  Attributes:
    size: int byte length of key modulus

  Properties:
    exponent: LongProperty int; public key component
    modulus: LongProperty int; public key component
    decrypt: LongProperty int; private key component

  Example:
    Assume `db_key` maps to a valid public/private RSAKey in the datastore.
    >>> key = RSAKey.get(db_key)
    ... cypher = key.private(message)
    ... message2 = key.public(cypher)
    ... assert message == message2
  """
  
  exponent = LongProperty(required=True, default=EXP)
  modulus = LongProperty(required=True)
  decrypt = LongProperty()
  
  @property
  def size(self):
    return len(integers.int_to_bytes(self.modulus))
    
  def private(self, data):
    """Private Key Transform: decrypt, sign
    
    Args:
      data: str of bytestring to transform
    Returns:
      str: of bytestring of transformed `data`
    Raises:
      ValueError: Data too long for key size.
      AttributeError: No private component in encryption key.
    """
    cypher = integers.bytes_to_int(data)
    
    if self.modulus <= cypher:
      raise ValueError, "Data too long for key size."
    elif not self.decrypt:
      raise AttributeError, "No private component in encryption key."
    
    message = pow(cypher, self.decrypt, self.modulus)
    return integers.int_to_bytes(message)

  def public(self, data):
    """Public Key Transform: encrypt, verify
    
    Args:
      data: str of bytestring to transform
    Returns:
      str: of bytestring of transformed `data`
    Raises:
      ValueError: Data too long for key size.
    """
    message = integers.bytes_to_int(data)
    
    if self.modulus <= message:
      raise ValueError, "data too long for key size"
    
    cypher = pow(message, self.exponent, self.modulus)
    return integers.int_to_bytes(cypher)
    
  def generate(self, f_prime, size=128):
    """Generate a new RSA public and private key pair.

    This function is not tested.
    
    Args:
      f_prime: func(arg) returns prime number of arg byte length
      size: int of modulus byte length
    """
    p = f_prime(size//2)
    q = f_prime(size//2)
    self.modulus = p * q
    self.exponent = EXP
    self.decrypt = integers.mmi(self.exponent, integers.lcm(p-1, q-1))
    
