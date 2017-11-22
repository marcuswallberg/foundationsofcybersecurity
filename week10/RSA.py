"""
Our own implementation of RSA

Authors:
Marcus Wallberg & Johanna Gustafsson

"""

from Crypto.Util import number
from random import randint
from os import urandom
from sundaram import * # Our own prime number generator
from time import time
from Crypto.Hash import SHA256

class RSA:

	def H( self, x):
		h = SHA256.new()
		h.update( bytes(x) )
		return h.hexdigest()

	def Gen( self, minPrime ):
		p = number.getPrime( minPrime )	# We are using the prime number from pycrypto for bench testing
		q = number.getPrime( minPrime )

		n = p * q
		phi = ( p - 1 ) * ( q - 1 )

		e = 0
		g = 0
		d = 0
		while g != 1 or d < 1:
			e = randint( 2, phi )
			g, d, _ = self.egcd( e, phi )

		self.pubKey = e, n
		self.privKey = d, n

		return self.pubKey, self.privKey

	def Enc( self, msg, pubKey = None):
		if not pubKey:
			pubKey = self.pubKey
		e, n = pubKey
		msg = bytes( msg.encode("utf-8") ).hex()
		msg = int( msg, 16 )

		if (n < msg):
			raise Exception("n is smaller than msg, make the message short or min prime longer")
		self.ctxt = pow( msg, e, n )
		return self.ctxt

	def Dec( self, ctxt = None, privKey = None):
		if not privKey:
			privKey = self.privKey
		if not ctxt: 
			ctxt = self.ctxt
		d, n = privKey
		msgInt = pow( ctxt, d, n )
		msgHex = hex( msgInt )
		msgB = bytes.fromhex( msgHex[2:] )
		msg = msgB.decode( "utf-8" )
		return msg

	def Sign( self, msg, privKey = None ):
		if not privKey:
			privKey = self.privKey
		d, n = privKey
		hashToInt = int( self.H( msg.encode("utf-8") ), 16 )
		signed = pow( hashToInt, d, n )
		return signed

	def Verify( self, msg, signature, pubKey = None ):
		if not pubKey:
			pubKey = self.pubKey
		e, n = pubKey
		decrypt = pow( signature, e, n )
		msgHashToInt = int( self.H( msg.encode("utf-8") ), 16 )
		assert( decrypt == msgHashToInt )
		return True

	def main():
		n, e, d = Gen( 2048 )
		privKey = [d, n]
		pubKey = [n, e]
		msg = "hello"

		ctxt = Enc(pubKey, msg)
		decMsg = Dec(privKey, ctxt)

		assert( decMsg == msg )

		signature = Sign( privKey, msg )
		Verify( pubKey, msg, signature )

	# ----------------
	# HELPER FUNCTIONS
	# ----------------
	def egcd( self, a, b ):
		s = 0; old_s = 1
		t = 0; old_t = 0
		r = b; old_r = a

		while r != 0:
			quotient =  old_r // r 
			old_r, r = r, old_r - quotient * r
			old_s, s = s, old_s - quotient * s
			old_t, t = t, old_t - quotient * t

		return old_r, old_s, old_t

	def getD( self, e, phi):
	    r, s, t = egcd( e, phi )
	    return r % phi
