"""
HOMEWORK 12, ASSIGNMENT 1
Authors:
Marcus Wallberg & Johanna Gustafsson
"""

from Crypto.Util.number import getPrime
from math import gcd, sqrt
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

def Gen( minSize = 16 ):
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
	pubKey, privKey = Gen()
	AliceX = int( input('Alice x as integer: ') )
	AliceY = int( input('Alice y as integer: ') )
	BobX = int( input('Bob x as integer: ') )
	BobY = int( input('Bob y as integer: ') )
	
	# Alice sends Enc(Ax^2), Enc(-2Ax), Enc(Ay^2), Enc(-2Ay)
	AliceSends = [ Enc( AliceX ** 2, pubKey ), Enc( 2 * AliceX, pubKey ), \
				   Enc( AliceY ** 2, pubKey ), Enc( 2 * AliceY, pubKey ) ]
	print( "Alice sends Enc(Ax^2), Enc(-2Ax), Enc(Ay^2), Enc(-2Ay)\n", AliceSends )

	# Bob sends Enc(Bx^2), Enc(2-Ax)*Bx, Enc(By^2), Enc(-2y)*By
	BobSends = [ Enc( BobX ** 2, pubKey ), pow(AliceSends[1], -BobX), \
				   Enc( BobY ** 2, pubKey ), pow(AliceSends[3], -BobY) ]
	print( "Bob sends Enc(Bx^2), Enc(2-Ax)*Bx, Enc(By^2), Enc(-2y)*By\n", BobSends )

	d1 = AliceSends[0] * BobSends[1] * BobSends[0] 
	d2 = AliceSends[2] * BobSends[3] * BobSends[2]
	distance = Dec( int(d1 * d2), privKey )

	print(distance)
	print(sqrt(distance))

if __name__ == '__main__':
	main()

