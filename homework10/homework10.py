from certificate3 import *
from classwork8 import *

# Initializing the CA
KEY_SIZE = 512
root = Block( "root", KEY_SIZE )
root.createCertificate( root.name, root.pubKey )
root.sign( root.privKey )

# Creating the CA for Alice and Bob
aliceCA = Block( "Alice", KEY_SIZE )
aliceCA.createCertificate( root.name, root.pubKey )
aliceCA.sign( root.privKey )
bobCA = Block( "Bob", KEY_SIZE )
bobCA.createCertificate( root.name, root.pubKey )
bobCA.sign( root.privKey )

# Verify the Certificate
aliceCA.verify( bobCA.certificate, bobCA.signature, root.pubKey )
bobCA.verify( aliceCA.certificate, aliceCA.signature, root.pubKey )

# Alice sending the symmetric key to Bob
symmetricKey = "very secret key!"
aliceRSA = RSA()
aliceRSA.pubKey = bobCA.pubKey
bobRSA = RSA()
bobRSA.privKey = bobCA.privKey
password2Bob = aliceRSA.Enc( symmetricKey )
bobReceivesPassword = bobRSA.Dec( password2Bob ) 
assert( symmetricKey == bobReceivesPassword )

# Start talking, code from classwork 8
alice = Peer( symmetricKey, "alice")
bob = Peer( bobReceivesPassword, "bob")
msg1 = alice.send("Msg from alice to bob")
print(bob.receive(msg1))
msg2 = alice.send("Another msg from alice to bob")
print(bob.receive(msg2))
msg3 = bob.send("Hello alice")
print(alice.receive(msg3))


