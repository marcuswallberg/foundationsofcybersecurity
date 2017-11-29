# Use one of these
import cbor
import json
from Crypto.Hash import SHA256
from time import time

# My version of RSA:
from RSA import RSA

# • public key of the certificate owner
# • public key algorithm used
# • name of the person or organization to whom the certificate was issued
# • date that the public key expires
# • name of the issuing certificate authority
# • serial number assigned to the digital certificate
# • URL of the relevant certificate revocation list
# • certificate signature algorithm
# • digital signature of the issuing certificate authority

class Block:
    def __init__(self, name, blockList):
        self.name = name
        self.blockList = blockList
        
    def getName( self ):
        return self.name
        
    def createCertificate(self, issuer, subject, subjectPubKey, issuerPrivKey): 
        self.certificate = { 
            'issuer' : issuer, 
            'subject' : subject, 
            'subjectPubKey' : subjectPubKey, 
            'issuerPrivKey' : issuerPrivKey,
            'currentTime' : time(), 
            'expirationTime' : time() + 100000,
            }
        return self.certificate

    def sign( self, certificate, privateKey ):
        r = RSA()
        msg = cbor.dumps( certificate )
        h = SHA256.new()
        h.update( msg )
        hashedMessage = h.hexdigest()
        signed = r.Sign( hashedMessage, privateKey )
        return signed

    def verify( self, certificate, signature, publicKey ):
        r = RSA()
        msg = cbor.dumps( certificate )
        h = SHA256.new()
        h.update( msg )
        hashedMessage = h.hexdigest()
        r.Verify( hashedMessage, signature, pubKey = publicKey )
        

    def createKeys( self, keysize ):
        r = RSA()
        pubKey, privKey = r.Gen( keysize )
        return pubKey, privKey
        
signed_certs = []

b = Block(0)
chain = []
chain.append(b)
googPub, googPriv = chain[0].createKeys(255)
prevPub, prevPriv = chain[0].createKeys(255)
cert = chain[0].createCertificate("Google", chain[0].getName(), googPub, prevPriv)
signed_certs.append(chain[0].sign(cert, prevPriv))

for n in range(1,9):
    b = Block(n, b)
    chain.append( b )
    pub, priv = chain[n].createKeys(255)
    cert = chain[n].createCertificate(chain[n-1].getName(), chain[n].getName(), prevPriv, priv)
    signed_certs.append(chain[n].sign(cert, prevPriv))
    prevPub = pub
    prevPriv = priv
        
