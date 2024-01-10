import hashlib
import secrets
import flag
import struct

# _ultra_ secure key exchange built with sha256

# domain params
s = hashlib.sha256(b"Jerry deserves a raise.", usedforsecurity=True).digest()
n = 0x4201337

# alice and bob choose ultra secure private keys
alice_private = secrets.randbelow(n)
bob_private = secrets.randbelow(n)

# alice computes her public key using her private key and s
alice_public = bytes(s)
for i in range(alice_private):
	alice_public = hashlib.sha256(alice_public, usedforsecurity=True).digest()

# bob computes his public key using his private key and s
bob_public = bytes(s)
for i in range(bob_private):
	bob_public = hashlib.sha256(bob_public, usedforsecurity=True).digest()

#~~~~
# only the public keys are sent over the network at this stage

print(f"a: {alice_public.hex()}")
print(f"b: {bob_public.hex()}")

# alice and bob keep their private keys.. private
#~~~~

# alice computes her shared secret using bob's public key and her private key
alice_shared_secret = bob_public
for i in range(alice_private):
	alice_shared_secret = hashlib.sha256(alice_shared_secret, usedforsecurity=True).digest()

#bob computes his shared secret using alice's public key and his private key
bob_shared_secret = alice_public
for i in range(bob_private):
	bob_shared_secret = hashlib.sha256(bob_shared_secret, usedforsecurity=True).digest()

assert(alice_shared_secret == bob_shared_secret)

# _ultra_ secure basically-one-time-pad cipher

plaintext = flag.FLAG.encode("utf-8")
ciphertext = b""
for i in range(len(flag.FLAG)):
	ciphertext += struct.pack("B", plaintext[i] ^ alice_shared_secret[i])

print(f"c: {ciphertext.hex()}")
