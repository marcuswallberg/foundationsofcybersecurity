"""
Timing attacks
"""

from classRSA import *

def main():
	keylengths = [64 * 2 ** x for x in range(1, 5)]

	print("Decryption time:")
	print(keylengths)
	for k in keylengths:
		n, e, d = Gen( k )
		privKey = [d, n]
		pubKey = [n, e]
		msg = 123456
		if( n < msg ):
			exit()

		ctxt = Enc( pubKey, msg )

		start = time()
		plaintxt = Dec( privKey, ctxt )
		print( time() - start )

if __name__ == '__main__':
	main()