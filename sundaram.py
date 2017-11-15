"""
Implementation of Sieve of Sundaram
Authors: Marcus Wallberg, Johanna Gustafsson
"""
from math import floor
from random import choice

# Returns a list of primes 
def sundaram( min = 0, max = 1000 ):

	n = floor( max / 2 )

	indicator = [ 1 for x in range( n + 1 ) ]

	# Marks all the numbers that we take 
	for i in range( 1, n ):
		for j in range( i, n ):
				index = i + j + 2 * i * j
				if index > n:
					break
				indicator[ index ] = 0

	# Adds all numbers 2n + 1 to primes if they  
	# are not set to 0 in the indicator for loop
	primes = []
	for i in range( n ):
		if indicator[i]:
			primes.append( 2 * i + 1 )

	# We have to manually the first prime
	primes[0] = 2

	# Removes all the primes below min
	for index, prime in enumerate( primes ):
		if prime >= min:
			primes = primes[index:]
			break

	return primes

# Returns one prime
def getPrime( min = 0, max = 1000 ):
	primes = sundaram( min, max )
	return choice( primes )
