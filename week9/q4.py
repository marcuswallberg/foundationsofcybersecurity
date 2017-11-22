from Crypto.Util import number
from random import randint
from os import urandom
from sundaram import * # Our own prime number generator
from time import time
from Crypto.Hash import SHA256

def H(x):
	h = SHA256.new()
	h.update( bytes(x) )
	return h.hexdigest()

def Gen( minPrime ):
	p = number.getPrime( minPrime )	# We are using the prime number from pycrypto for bench testing
	q = number.getPrime( minPrime )
	# p = getPrime(minPrime, minPrime + 500)
	# q = getPrime(minPrime, minPrime + 500) # We could get the same prime here

	n = p * q
	phi = ( p - 1 ) * ( q - 1 )

	e = 0
	g = 0
	d = 0
	while g != 1 or d < 1:
		e = randint( 2, phi )
		g, d, _ = egcd( e, phi )

	return n, e, d

def Enc(pubKey, msg):
	n, e = pubKey
	msg = bytes( msg.encode("utf-8") ).hex()
	msg = int( msg, 16 )

	if (n < msg):
		print("n is smaller!")
		exit()
	return pow( msg, e, n )

def Dec(privKey, ctxt):
	d, n = privKey
	msgInt = pow( ctxt, d, n )
	msgHex = hex( msgInt )
	msgB = bytes.fromhex( msgHex[2:] )
	msg = msgB.decode( "utf-8" )
	return msg

def Sign(privKey, msg):
	d, n = privKey
	hashToInt = int( H(msg.encode("utf-8")), 16 )
	signed = pow( hashToInt, d, n )
	return signed

def Verify(pubKey, msg, signature):
	n, e = pubKey
	decrypt = pow( signature, e, n )
	msgHashToInt = int(H(msg.encode("utf-8")),16)
	assert( decrypt == msgHashToInt )

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
def egcd( a, b ):
	s = 0; old_s = 1
	t = 0; old_t = 0
	r = b; old_r = a

	while r != 0:
		quotient =  old_r // r 
		old_r, r = r, old_r - quotient * r
		old_s, s = s, old_s - quotient * s
		old_t, t = t, old_t - quotient * t

	return old_r, old_s, old_t

def getD(e, phi):
    r, s, t = egcd( e, phi )
    return r % phi

if __name__ == '__main__':
	main()