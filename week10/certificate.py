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
    def __init__(self, name):
        self.name = name
        
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
        
chain = []
certs = []
signed_certs = []
pub_keys = []

keysize = 512

b = Block(0)
chain.append(b)
googPub, googPriv = chain[0].createKeys(keysize)
prevPub, prevPriv = chain[0].createKeys(keysize)
cert = chain[0].createCertificate("Google", chain[0].getName(), googPub, prevPriv)
certs.append(cert)
signed_certs.append(chain[0].sign(cert, prevPriv))
pub_keys.append(prevPub)

for n in range(1,9):
    b = Block(n)
    chain.append( b )
    pub, priv = chain[n].createKeys(keysize)
    cert = chain[n].createCertificate(chain[n-1].getName(), chain[n].getName(), prevPriv, priv)
    
    for m in [x for x in reversed(range(1, n))]:
        if (m is 1):
            chain[n].verify(certs[m-1], signed_certs[m-1], pub_keys[m-1])
        else:
            chain[n].verify(certs[m-1], signed_certs[m-1], pub_keys[m-2])
            print(certs[m-2]['subject'], certs[m-1]['issuer'])

            assert( certs[m-2]['subject'] == certs[m-1]['issuer'] )
            
        assert(time() <= certs[m-1]['expirationTime']) 
        assert(time() >= certs[m-1]['currentTime'])
    
    certs.append(cert)
    signed_certs.append(chain[n].sign(cert, prevPriv))
    pub_keys.append(pub)
    prevPub = pub
    prevPriv = priv

