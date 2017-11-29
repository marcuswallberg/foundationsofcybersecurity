"""
Modified code from: https://gist.github.com/swinton/8409454

Authors:
Marcus Wallberg & Johanna Gustafsson

"""

import json
from os import urandom

from Crypto import Random
from Crypto.Cipher import AES

# PADDING
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
        chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class AESCipher:

    def __init__( self, keylength ):
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

def main():
    cipher = AESCipher( 32 )
    encrypted = cipher.encrypt('Secret Message A')
    decrypted = cipher.decrypt(encrypted)
    print( encrypted )
    print( decrypted )

if __name__ == '__main__':
    main()