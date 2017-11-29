from RSA import RSA
from Crypto.Util import number
from os import urandom
from aes import *
from time import time
import json

# The server
class KDC:
	# List of RSA keys and common AES keys
	keys = {}

  # We set the default key size
	def __init__( self, keySize ):
		self.keySize = keySize

	def addClientKey( self, id, key ):
		self.keys[id.hex()] = key

  # Sending [ Alice, Bob ]
  # Returns EncKA(KAB, EncKB(Alice,KAB))
	def setUpCommonKey( self, clientIdA, clientIdB ):
		r = RSA()
		
		_aes = AESCipher( 32 )
		KABkey = _aes.key.hex()

		KABid = json.dumps( { 'A' : clientIdA.hex(), 'B' : clientIdB.hex() } )	# Making the ID a string
		self.keys[KABid] = KABkey	# Storing the common key and id 

		EncKA = r.Enc( msg = KABkey, pubKey = self.keys[clientIdA.hex()] )
		EncKB = r.Enc( msg = KABkey, pubKey = self.keys[clientIdB.hex()] )
		AliceId = _aes.encrypt( msg = clientIdA.hex() )

		message = json.dumps( { 'A': EncKA, 'B': EncKB, 'ID': AliceId } )
		return message

# Alice and Bob class
class Client:
	def __init__( self, keySize ):
		self.r = RSA() 	# Using our own RSA
		self.pubKey, self.privKey = self.r.Gen( keySize )	# Getting the private and public keys
		self.identity = urandom( keySize )

	def decryptCommonKey( self, ctxt ):
		self._aes = AESCipher( 32 )
		self.commonKey =  bytes.fromhex( self.r.Dec( ctxt = ctxt ) )
		self._aes.setKey( self.commonKey )	# Setting the common key

	def decryptMessage( self, ctxt ):
		msg = self._aes.decrypt( ctxt )
		return msg

	def encyptMessage( self, msg ):
		return self._aes.encrypt( msg )

# Returns ~87 keys per second
def timeKDC():
	# Set up
	keySize = 512
	K = KDC( keySize )
	
	iterations = 100
	Alice = Client( keySize )
	Bob = Client( keySize )
	K.addClientKey( Alice.identity, Alice.pubKey )
	K.addClientKey( Bob.identity, Bob.pubKey )

	start = time()
	for _ in range(iterations):
		K.setUpCommonKey( Alice.identity, Bob.identity )

	totalTime = time() - start
	keysPerSecond = iterations / totalTime
	print('Total time:', totalTime)
	print('Key per second:', keysPerSecond)

# This function runs the program
def main():
	# Initialize the objects
	keySize = 512
	K = KDC( keySize )
	Alice = Client( keySize )
	Bob = Client( keySize )

	# Setting up the keys on the server
	K.addClientKey( Alice.identity, Alice.pubKey )
	K.addClientKey( Bob.identity, Bob.pubKey )

	# Alice getting the KAB and the message to Bob
	EncKA, EncKB, AliceId = json.loads( K.setUpCommonKey( Alice.identity, Bob.identity ) ).values()

	Alice.decryptCommonKey( EncKA )
	Bob.decryptCommonKey( EncKB )

	assert( Alice.commonKey == Bob.commonKey )
	assert( Bob.decryptMessage( AliceId ) == Alice.identity.hex() )

if __name__ == '__main__':
	timeKDC()







