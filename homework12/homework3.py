from RSA import *
from random import randint
from Crypto.Cipher import AES
from Crypto import Random
from random import shuffle

import json
from os import urandom

# PADDING
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
        chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class AESCipher:

    def __init__( self, keylength=16 ):
        # self.key = bytes(key.encode("utf-8"))
        self.key = urandom( keylength )

    def setKey( self, key ):
        self.key = key

    def encrypt( self, msg ):
        msg = pad( msg )
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        byteMessage = cipher.encrypt( bytes(msg.encode("utf-8")) ).hex()
        return json.dumps( { 'iv':iv.hex(), 'ctxt':byteMessage } )

    def decrypt( self, ctxt ):
        iv, ctxt = json.loads( ctxt ).values()
        iv = bytes.fromhex( iv )
        ctxt = bytes.fromhex( ctxt )
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        msg = cipher.decrypt( ctxt ) 
        return unpad( msg ).decode("utf-8")

def obliviousTransfer(AliceMessage, BobChoice, N, e, d):
	max = 100
	x0 = randint(1, max)
	x1 = randint(1, max)
	x = [x0, x1]
	x = x[BobChoice]
	k = randint(1, max)
	v = pow(k, e , N)
	v += x % N
	k0 = pow((v - x0), d, N)
	k1 = pow((v - x1), d, N)
	m0, m1 = AliceMessage
	m0prim = m0 + k0
	m1prim = m1 + k1
	mprim = [m0prim, m1prim]
	BobMessage = mprim[BobChoice] - k
	return BobMessage

def main():
	r = RSA()
	pubKey, privKey = r.Gen( 64 )
	e, n = pubKey
	d, _ = privKey

	AliceChoice = bool(int(input("Alice binary Choice: ")))
	BobChoice = bool(int(input("Bob binary Choice: ")))

	answers = ['00', '10', '10', '01' ]

	aesOuter = []
	for _ in range(2):
		aes = AESCipher()
		aesOuter.append( aes )
		aesOuter.append( aes )

	aesOuterKey = []
	aesOuterKey.append(aesOuter[0].key)
	aesOuterKey.append(aesOuter[2].key)

	aesInner = []
	aesInnTemp1 = AESCipher()	
	aesInnTemp2 = AESCipher()	
	for _ in range(2):
		aesInner.append( aesInnTemp1 )
		aesInner.append( aesInnTemp2 )

	aesInnerKey = []
	aesInnerKey.append(aesInner[0].key)
	aesInnerKey.append(aesInner[1].key)
	
	sendToBob = []
	for i in range(4):
		cipherInner = aesInner[i].encrypt( answers[i] )
		sendToBob.append( aesOuter[i].encrypt( cipherInner ) )

	# Alice sends this to bob:
	outerKeyToBob = aesOuterKey[AliceChoice]
	shuffle(sendToBob)

	AliceOT = [ int(aesInnerKey[0].hex(),16), int(aesInnerKey[1].hex(), 16) ]
	oT = obliviousTransfer( AliceOT, BobChoice, n, e, d )
	
	BobInnerKey = bytes.fromhex( hex( oT )[2:] )
	print( BobInnerKey )

	BobAES = AESCipher()
	BobAES.key = outerKeyToBob
	decryptList = []
	for i in range(4):
		try:
			decryptList.append( BobAES.decrypt( sendToBob[i] ) )
		except:
			pass
	
	BobAES.key = BobInnerKey
	for cipher in decryptList:
		try:
			print("Format: [SUM CARRY]")
			print( BobAES.decrypt( cipher ) ) 
		except: 
			pass


if __name__ == '__main__':
	main()