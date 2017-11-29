from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import hashlib
import numpy as np
from time import time

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class Peer(object):
	def __init__(self, key, name):
		h = SHA512.new()
		key = key.encode("utf-8")
		key = bytes(key).zfill(32)
		if name == "alice":
			self.receiveAuthKey = h.update( key + "Bob2AliceAuth".encode("utf-8") )
			self.receiveAuthKey = bytes.fromhex(h.hexdigest()).zfill(64); h = SHA512.new()
			self.sendAuthKey = h.update( key + 	"Alice2BobAuth".encode("utf-8") )
			self.sendAuthKey = bytes.fromhex(h.hexdigest()).zfill(64); h = SHA512.new()
			self.receiveEncKey = h.update( key + 	"Bob2AliceEnc".encode("utf-8") )
			self.receiveEncKey = bytes.fromhex(h.hexdigest()).zfill(64); h = SHA512.new()
			self.sendEncKey = h.update( key + 	"Alice2BobEnc".encode("utf-8") )
			self.sendEncKey = bytes.fromhex(h.hexdigest()).zfill(64)
		elif name == "bob":
			h = SHA512.new()
			self.receiveAuthKey = h.update( key + "Alice2BobAuth".encode("utf-8") )
			self.receiveAuthKey = bytes.fromhex(h.hexdigest()).zfill(64); h = SHA512.new()
			self.sendAuthKey = h.update( key + 	"Bob2AliceAuth".encode("utf-8") )
			self.sendAuthKey = bytes.fromhex(h.hexdigest()).zfill(64); h = SHA512.new()
			self.receiveEncKey = h.update( key + 	"Alice2BobEnc".encode("utf-8") )
			self.receiveEncKey = bytes.fromhex(h.hexdigest()).zfill(64); h = SHA512.new()
			self.sendEncKey = h.update( key + 	"Bob2AliceEnc".encode("utf-8") )
			self.sendEncKey = bytes.fromhex(h.hexdigest()).zfill(64)
		else:
			print( "Wrong name!" )
			exit()

		self.count = -1
		
	def send(self, msg):

		h = SHA512.new()
		
		c = AES.new(self.sendEncKey[:32], AES.MODE_ECB)

		msg = msg.zfill(32).encode("utf-8")
		cipher = c.encrypt( msg )

		ctag = cipher
		h.update( ctag )
		tag = h.hexdigest()
		protected_msg = cipher, ctag

		return protected_msg 

	def receive(self, protected_msg):
		c = AES.new(self.receiveEncKey[:32], AES.MODE_ECB)

		cipher, ctag = protected_msg

		# cipher = bytes.fromhex(cipher)
		msg = c.decrypt( cipher )
		msg = msg.decode("utf-8").strip("0")

start = time()
# Example

for _ in range(100000):
	alice = Peer("very secret key!", "alice")
	bob = Peer("very secret key!", "bob")
	msg1 = alice.send("Msg from alice to bob")
	bob.receive(msg1)
	msg2 = alice.send("Another msg from alice to bob")
	bob.receive(msg2)
	msg3 = bob.send("Hello alice")
	alice.receive(msg3)

t = time() - start
print("Elapsed time: {t} seconds".format(t = t))
