"""
Timing attacks
"""

from classRSA import *

def main():
	keylengths = [32 * 2 ** x for x in range(1, 5)]
	timings = []
	cyphertexts = []
	n_list = []

	# Measure some decryption times
	print("Decryption time:")
	print(keylengths)
	for k in keylengths:
		n, e, d = Gen( k )
		print(d)
		n_list.append(n)
		privKey = [d, n]
		pubKey = [n, e]
		msg = 123456
		if( n < msg ):
			exit()

		ctxt = Enc( pubKey, msg )
		cyphertexts.append(ctxt)

		start = time()
		plaintxt = Dec( privKey, ctxt )
		timings.append( time() - start )

	# Start the timing attacks
	for t, c, n in zip( timings, cyphertexts, n_list ):
		d = 31303221126132808284353519642319508 	# Start with a big number
		m = 0
		tryTime = 0
		# This algorithm needs to be more efficient
		while (t - tryTime) > 0.000001: # How close you want to get
			start = time()
			m = pow(c, d, n)
			tryTime = time() - start
			d += 1
		print( m == msg )

if __name__ == '__main__':
	main()