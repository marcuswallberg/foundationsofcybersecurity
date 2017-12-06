"""
HOMEWORK 12, EXERCISE 1
Authors:
Marcus Wallberg & Johanna Gustafsson
"""

from Crypto.Util.number import getPrime
from math import gcd
from random import randint

# =================+
# STOLEN FUNCTIONS |

def lcm(x, y):
   lcm = (x * y) // gcd(x,y)
   return lcm

def modinv(a, p, maxiter=1000000):
    assert(a != 0)
    r = a
    d = 1
    for i in range( min (p, maxiter) ):
        d = ((p // r + 1) * d) % p
        r = (d * a) % p
        if r == 1:
            break
    return d

# END OF STOLEN FUNCTIONS |
# ========================+

# The rest are our implementation
def Enc( message, pubKey ):
	n, g = pubKey
	assert( 0 <= message and message <= n )
	r = randint(0, n)
	cipher = pow(g, message, n ** 2 ) * pow(r, n, n ** 2) % n ** 2
	assert( cipher <= n ** 2 )
	return cipher

def Dec( cipher, privKey ):
	lamb, mu, n = privKey
	x = pow(cipher, lamb, n ** 2) - 1
	m = modinv(lamb, n)
	message = ((x // n) * m) % n
	return message

def Gen( minSize = 64 ):
	p = getPrime( minSize )
	q = getPrime( minSize )
	assert( gcd(p*q,(p-1)*(q-1)) == 1 )

	n = p * q
	g = n + 1
	lamb = (p - 1) * (q - 1)
	mu = modinv( lamb, n ) 

	pubKey = n, g
	privKey = lamb, mu, n

	return pubKey, privKey

def main():
	print( "\n" + "-" * 26 ); print("Homework 12, Assignment 11"); print( "-" * 26, "\n" )
	message = int( input('Alice message as integer: ') )
	pubKey, privKey = Gen()
	print( "public key:", pubKey )
	print( "private key:", privKey, "\n" )
	cipher = Enc( message, pubKey )
	print( "cipher text:", cipher, "\n" )
	message = Dec( cipher, privKey )
	print( "decrypted plaintext:", message )

if __name__ == '__main__':
	main()

