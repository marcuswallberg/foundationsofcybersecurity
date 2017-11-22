from random import randint
from os import urandom
import math
from Crypto.Hash import SHA256
from Crypto.Util import number

MIN_P_SIZE = 200

# STEP 1: ALICE TO BOB
# ------------------------------------------------
Sa = randint( 1,200 ) # get min p size
N = urandom( randint(0,256) )   # Random in bytes

alice2bob = [Sa, N] # send to bob

# STEP 2: BOB TO ALICE
# ------------------------------------------------
Sa, N = alice2bob
Sb = randint( 1,200 ) # get min p size

S = max(Sa, Sb)
assert (S <= 2*Sb)

#Choose (g, p, q)
def choose_gpq(min_size):
    q = number.getPrime(min_size)
    p = 2*q + 1
    while (!number.isPrime(p)):
        q = number.getPrime(min_size)
        p = 2*q + 1
    alpha = randint(2, p-2)
    g = alpha ** 2 % p
    while (g == 1 or g == p-1):
        alpha = randint(2, p-2)
        g = alpha ** 2 % p
    return (g, p, q)

g, p, q = choose_gpq(S-1)

b = randint(1, q-1)
B = (g**b) % p

# STEP 3: ALICE TO BOB
# ------------------------------------------------
# check AUTHBob

# Check validity of p
assert (Sa-1 <= math.log(p, 2))
assert (2*Sa >= math.log(p, 2))
assert (255 <= math.log(p,2)) 
assert (256 >= math.log(p,2))
assert (number.isPrime(p))
assert (number.isPrime(q))
assert ((p-1) % q == 0)
assert (g != 1 and (g**q % p == 1))
assert (B!=1 and (B**q % p == 1))
a = random(1, q-1)
A = (g**a) % p

# STEP 4: BOB ASSERTS
# ------------------------------------------------
#check A, AUTHAlice
h = SHA256.new();h.update( bytes(str(A).encode("utf-8")) )
assert( h.hexdigest() == AUTHAlice ) 
assert( A != 1 )
assert( Aq == 1 )


Bob_Kprim = A ** b % p
h = SHA256.new(); h.update( bytes(str(Bob_Kprim).encode("utf-8")) ) 
Bob_K = h.hexdigest()

Alice_Kprim = B ** a % p
h = SHA256.new(); h.update( bytes(str(Alice_Kprim).encode("utf-8")) ) 
Alice_K = h.hexdigest()
