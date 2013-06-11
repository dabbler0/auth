#!/usr/bin/env python
import auth
import random
import simplejson as json

def test():
  print "DATABASE TESTS\n"
  conn = auth.initDB("test.db")
  random_number = random.randint(0, 500)
  print "Set salt: %d" % random_number
  auth.setHex(conn, auth.SALT, "Mr. Mustafa", random_number)
  retrieved_random_number = auth.getHex(conn, auth.SALT, "Mr. Mustafa")
  print "Got salt: %d" % retrieved_random_number
  assert (retrieved_random_number == random_number), "setHex/getHex do not match"
  
  print "\n\nKEY GENERATION TESTS\n"
  keydict = auth.generateKey(conn, "Mr. Mustafa", random.randint(0, 500))
  print "Generated session key %s" % auth.hexify(keydict["K"])
  print "Verification hash is %d" % keydict["M"]

  print "\n\nENCRYPTION TESTS\n"
  message = """
    And Aaron would have to explain
    about the modular design of the coffins
    and how they could be folded up
    and put inside one another
    "They are not one use only", he would say
    "They are recyclable"
  """
  
  print "\nTrue encryption\n"
  
  encrypted = auth.encrypt(keydict["K"], message)
  print "Encrypted to \"%s\"" % encrypted
  decrypted = auth.decrypt(keydict["K"], encrypted)
  print "Decrypted to \"%s\"" % decrypted
  assert (decrypted == message), "encrypt/decrypt do not match"
  
  print "\nFalse encryption\n"

  encrypted = auth.encrypt("Incorrect keyIncorrect keyIncorr", message)
  print "False encrypted to \"%s\"" % encrypted
  decrypted = auth.decrypt(keydict["K"], encrypted)
  assert (decrypted == None), "Accepted false information"
  if (decrypted == None):
    print "Rejected false information"

test()
