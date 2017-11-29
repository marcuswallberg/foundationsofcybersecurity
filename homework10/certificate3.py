# Use one of these
import cbor
import json
from Crypto.Hash import SHA256
from time import time

# My version of RSA:
from RSA import RSA

class Block:
    def __init__(self, name, keysize):
        self.name = name
        self.createKeys(keysize)
        
    def getName( self ):
        return self.name
        
    def createCertificate(self, issuer, issuerPubKey): 
        self.certificate = { 
            'issuer' : issuer, 
            'subject' : self.name, 
            'subjectPubKey' : self.pubKey, 
            'issuerPrivKey' : issuerPubKey,
            'currentTime' : time(), 
            'expirationTime' : time() + 100000
            }

    def sign( self, privateKey ):
        r = RSA()
        msg = cbor.dumps( self.certificate )
        h = SHA256.new()
        h.update( msg )
        hashedMessage = h.hexdigest()
        signed = r.Sign( hashedMessage, privateKey )
        self.signature = signed

    def verify( self, certificate, signature, publicKey ):
        r = RSA()
        msg = cbor.dumps( certificate )
        h = SHA256.new()
        h.update( msg )
        hashedMessage = h.hexdigest()
        r.Verify( hashedMessage, signature, pubKey = publicKey )
      
    def createKeys( self, keysize ):
        r = RSA()
        self.pubKey, self.privKey = r.Gen( keysize )

