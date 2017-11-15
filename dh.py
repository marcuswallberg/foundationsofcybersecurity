"""
Implementation of Diffie Hellman
Authors: Marcus Wallberg, Johanna Gustafsson
"""
from Crypto.Util import number
from random import randint
from sundaram import * 
import sys
import argparse
from math import log2, ceil
from os import urandom

def diffieHellman( MIN_NUMBER = 100, usePycryptoPrime = 0, p = 0 ):
	max = MIN_NUMBER + 1000

	g = 2	# The same as the benchmark tests
	a = 0
	b = 0

	# If p is 0 we generate p, otherwise we use the p input as prime
	if not p:
		if usePycryptoPrime:
			numberOfBytes = ceil( log2( MIN_NUMBER ) )
			p = number.getPrime( numberOfBytes ) # Pycrypto's implementation
		else:
			p = getPrime( MIN_NUMBER, max )	# Our implementation

		g = randint( MIN_NUMBER, max )

		a = randint( 1, MIN_NUMBER )      # a secret
		b = randint( 1, MIN_NUMBER )      # b secret
	else:
		a = int( urandom(640).hex(), 16 )	# The same size as the bench tests
		b = int( urandom(640).hex(), 16 )

	 
	# A = ( g ** a ) % p
	A = pow( g, a, p )
	B = pow( g, b, p )
	# B = ( g ** b ) % p
	 
	# secretA = ( B ** a ) % p
	secretA = pow( B, a, p )
	secretB = pow( A, b, p )
	# secretB = ( A ** b ) % p

	# Check if they are the same
	if secretA != secretB:
		print( "secretA:", secretA )
		print( "secretB:", secretB )
		raise Exception( "The secrets don't match" )

if __name__ == '__main__':
	diffieHellman()