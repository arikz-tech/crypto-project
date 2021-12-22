import Crypto.Util.number
from Crypto import Random
import Crypto
import libnum
from random import randint
import hashlib


def elgamal_digital_sign(message):
    msg = bytes()

    if type(message) is list:
        for block in message:
            msg += block
    elif type(message) is str:
        msg = message.encode()

    bits = 60
    q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    a = 2
    xa = randint(0, q - 1)
    ya = pow(a, xa, q)
    m = int.from_bytes(hashlib.sha1(msg).digest(), byteorder='big')
    k = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    k_inverse = (libnum.invmod(k, q - 1))

    s1 = pow(a, k, q)
    s2 = ((m - xa * s1) * k_inverse) % (q - 1)

    return a, q, ya, k, m, s1, s2


def elgamal_verify_signature(a, q, ya, m, s1, s2):
    v_1 = (pow(ya, s1, q) * pow(s1, s2, q)) % q
    v_2 = pow(a, m, q)

    return v_1 == v_2
