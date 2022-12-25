import random
import ecdsa
import hashlib

#random 256 bitds and generate private key
private_key = (random.getrandbits(256)).to_bytes(32, byteorder="little", signed=False)

#We give our private key and attach our private key to a specific type of curve SECP256k1
signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)

#Convert signing key into a verification key (a verification key is a 64 bytes long no. and it represnts a point on the curve x_cord: 32 bytes, y_cord: 32 bytes)
verifying_key = signing_key.get_verifying_key()
x_cor = bytes.fromhex(verifying_key.to_string().hex()[:32])
y_cor = bytes.fromhex(verifying_key.to_string().hex()[32:])

#Create a compressed public key, we supply x cordinate and expect the end user to calculate y cordinate by themselves
if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0:
    public_key = bytes.fromhex(f'02{x_cor.hex()}')
else:
    public_key = bytes.fromhex(f'03{x_cor.hex()}')

#use this public key and hash it
sha256_key = hashlib.sha256(public_key)
ripemd160_key = hashlib.new("ripemd160")
ripemd160_key.update(sha256_key.digest())
keyhash = ripemd160_key.digest()
