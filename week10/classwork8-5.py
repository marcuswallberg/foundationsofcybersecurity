from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import hashlib
import numpy as np
from os import urandom
import cbor
from time import time

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class Peer(object):
	def __init__(self, key, name):
		fill = 32
		h = SHA256.new()
		key = key.encode("utf-8")
		if name == "alice":
			self.receiveAuthKey = h.update( key + "Bob2AliceAuth".encode("utf-8") )
			self.receiveAuthKey = bytes.fromhex(h.hexdigest()).zfill(fill); h = SHA256.new()
			self.sendAuthKey = h.update( key + 	"Alice2BobAuth".encode("utf-8") )
			self.sendAuthKey = bytes.fromhex(h.hexdigest()).zfill(fill); h = SHA256.new()
			self.receiveEncKey = h.update( key + 	"Bob2AliceEnc".encode("utf-8") )
			self.receiveEncKey = bytes.fromhex(h.hexdigest()).zfill(fill); h = SHA256.new()
			self.sendEncKey = h.update( key + 	"Alice2BobEnc".encode("utf-8") )
			self.sendEncKey = bytes.fromhex(h.hexdigest()).zfill(fill)
		elif name == "bob":
			h = SHA256.new()
			self.receiveAuthKey = h.update( key + "Alice2BobAuth".encode("utf-8") )
			self.receiveAuthKey = bytes.fromhex(h.hexdigest()).zfill(fill); h = SHA256.new()
			self.sendAuthKey = h.update( key + 	"Bob2AliceAuth".encode("utf-8") )
			self.sendAuthKey = bytes.fromhex(h.hexdigest()).zfill(fill); h = SHA256.new()
			self.receiveEncKey = h.update( key + 	"Alice2BobEnc".encode("utf-8") )
			self.receiveEncKey = bytes.fromhex(h.hexdigest()).zfill(fill); h = SHA256.new()
			self.sendEncKey = h.update( key + 	"Bob2AliceEnc".encode("utf-8") )
			self.sendEncKey = bytes.fromhex(h.hexdigest()).zfill(fill)
		else:
			print( "Wrong name!" )
			exit()

		self.count = -1
		
	def send(self, msg):
		h = SHA256.new()
		iv = urandom(16)
		c = AES.new(self.sendEncKey[:32], AES.MODE_CBC, iv)
		msg = msg.encode("utf-8").zfill(32)
		cipher = c.encrypt( msg )
		ctag = cipher
		h.update( ctag )
		tag = h.hexdigest()
		protected_msg = cbor.dumps( [cipher, ctag, iv] )
		return protected_msg 

	def receive(self, protected_msg):
		cipher, ctag, iv = cbor.loads(protected_msg)
		c = AES.new(self.receiveEncKey[:32], AES.MODE_CBC, iv)
		msg = c.decrypt( cipher )
		msg = msg.decode("utf-8").strip("0")
		return msg

start = time()
# Example

for _ in range(1):
	alice = Peer("very secret key!", "alice")
	bob = Peer("very secret key!", "bob")
	msg1 = alice.send("Msg from alice to bob")
	bob.receive(msg1)
	msg2 = alice.send("Another msg from alice to bob")
	print(bob.receive(msg2))
	msg3 = bob.send("Hello alice")
	print(alice.receive(msg3))

t = time() - start
print("Elapsed time: {t} seconds".format(t = t))
