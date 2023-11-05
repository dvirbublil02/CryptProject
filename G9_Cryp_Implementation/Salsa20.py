import sys
import platform
import struct
import random

from numpy.compat import long

assert(sys.version_info >= (2, 6))

if sys.version_info >= (3,):
	integer_types = (int,)
	python3 = True
else:
	integer_types = (int, long)
	python3 = False

from struct import Struct
little_u64 = Struct( "<Q" )      #    little-endian 64-bit unsigned.
                                 #    Unpacks to a tuple of one element!

little16_i32 = Struct( "<16i" )  # 16 little-endian 32-bit signed ints.
little4_i32 = Struct( "<4i" )    #  4 little-endian 32-bit signed ints.
little2_i32 = Struct( "<2i" )    #  2 little-endian 32-bit signed ints.


class Salsa20(object):
    def __init__(self, key=None, IV=None, rounds=20):
        self._lastChunk64 = True
        self._IVbitlen = 64  # must be 64 bits
        self.ctx = [0] * 16
        if key:
            self.setKey(key)
        if IV:
            self.setIV(IV)

        self.setRounds(rounds)

    @staticmethod
    def generate_pseudo_random_key():
        key = ""
        for i in range(32):
            num = random.randint(ord('A'), ord('z'))
            key += chr(num)
        print("key = " + key)
        return key

    @staticmethod
    def to_bytearray(obj, obj_name='', encoding='utf-8', forcecopy=False):
        if obj is None:
            raise AttributeError("`%s` is None" % obj_name)
        if type(obj) == bytearray:
            if forcecopy:
                return bytearray(obj)
            return obj
        if type(obj) == str and str != bytes:
            return bytearray(obj, encoding)
        elif type(obj) in (int, float):
            raise AttributeError("`%s` must be a bytes-like object" % obj_name)
        else:
            return bytearray(obj)

    def setKey(self, key):
        if type(key) != bytes:
            key = self.to_bytearray(key)
        ctx = self.ctx
        if len(key) == 32:  # recommended
            constants = b"expand 32-byte k"
            ctx[1], ctx[2], ctx[3], ctx[4] = little4_i32.unpack(key[0:16])
            ctx[11], ctx[12], ctx[13], ctx[14] = little4_i32.unpack(key[16:32])
        elif len(key) == 16:
            constants = b"expand 16-byte k"
            ctx[1], ctx[2], ctx[3], ctx[4] = little4_i32.unpack(key[0:16])
            ctx[11], ctx[12], ctx[13], ctx[14] = little4_i32.unpack(key[0:16])
        else:
            print(str(len(key)))
            raise Exception("key length isn't 32 or 16 bytes.")
        ctx[0], ctx[5], ctx[10], ctx[15] = little4_i32.unpack(constants)


    def setIV(self, IV):
        assert type(IV) == bytes
        assert len(IV) * 8 == 64, 'nonce (IV) not 64 bits'
        self.IV = IV
        ctx = self.ctx
        ctx[6], ctx[7] = little2_i32.unpack(IV)
        ctx[8], ctx[9] = 0, 0  # Reset the block counter.

    setNonce = setIV  # support an alternate name

    def setCounter(self, counter):
        assert (type(counter) in integer_types)
        assert (0 <= counter < 1 << 64), "counter < 0 or >= 2**64"
        ctx = self.ctx
        ctx[8], ctx[9] = little2_i32.unpack(little_u64.pack(counter))

    def getCounter(self):
        return little_u64.unpack(little2_i32.pack(*self.ctx[8:10]))[0]

    def setRounds(self, rounds, testing=False):
        assert testing or rounds in [8, 12, 20], 'rounds must be 8, 12, 20'
        self.rounds = rounds

    def encryptBytes(self, data):

        if type(data) != bytes: #data must be byte string
            data = self.to_bytearray(data)

        assert self._lastChunk64, 'previous chunk not multiple of 64 bytes'
        lendata = len(data)
        munged = bytearray(lendata)
        for i in range(0, lendata, 64):
            h = salsa20_wordtobyte(self.ctx, self.rounds, checkRounds=False)
            self.setCounter((self.getCounter() + 1) % 2 ** 64)
            # Stopping at 2^70 bytes per nonce is user's responsibility.
            for j in range(min(64, lendata - i)):
                if python3:
                    munged[i + j] = data[i + j] ^ h[j]
                else:
                    munged[i + j] = ord(data[i + j]) ^ ord(h[j])

        self._lastChunk64 = not lendata % 64
        return bytes(munged)

    decryptBytes = encryptBytes  # encrypt and decrypt use same function

# --------------------------------------------------------------------------

def salsa20_wordtobyte(input, nRounds=20, checkRounds=True):
    """ Do nRounds Salsa20 rounds on a copy of
            input: list or tuple of 16 ints treated as little-endian unsigneds.
        Returns a 64-byte string.
        """

    assert (type(input) in (list, tuple) and len(input) == 16)
    assert (not (checkRounds) or (nRounds in [8, 12, 20]))

    x = list(input)

    def XOR(a, b):
        return a ^ b

    ROTATE = rot32
    PLUS = add32

    for i in range(nRounds):
        # These ...XOR...ROTATE...PLUS... lines are from ecrypt-linux.c
        # unchanged except for indents and the blank line between rounds:
        x[4] = XOR(x[4], ROTATE(PLUS(x[0], x[12]), 7));
        x[8] = XOR(x[8], ROTATE(PLUS(x[4], x[0]), 9));
        x[12] = XOR(x[12], ROTATE(PLUS(x[8], x[4]), 13));
        x[0] = XOR(x[0], ROTATE(PLUS(x[12], x[8]), 18));
        x[9] = XOR(x[9], ROTATE(PLUS(x[5], x[1]), 7));
        x[13] = XOR(x[13], ROTATE(PLUS(x[9], x[5]), 9));
        x[1] = XOR(x[1], ROTATE(PLUS(x[13], x[9]), 13));
        x[5] = XOR(x[5], ROTATE(PLUS(x[1], x[13]), 18));
        x[14] = XOR(x[14], ROTATE(PLUS(x[10], x[6]), 7));
        x[2] = XOR(x[2], ROTATE(PLUS(x[14], x[10]), 9));
        x[6] = XOR(x[6], ROTATE(PLUS(x[2], x[14]), 13));
        x[10] = XOR(x[10], ROTATE(PLUS(x[6], x[2]), 18));
        x[3] = XOR(x[3], ROTATE(PLUS(x[15], x[11]), 7));
        x[7] = XOR(x[7], ROTATE(PLUS(x[3], x[15]), 9));
        x[11] = XOR(x[11], ROTATE(PLUS(x[7], x[3]), 13));
        x[15] = XOR(x[15], ROTATE(PLUS(x[11], x[7]), 18));

        x[1] = XOR(x[1], ROTATE(PLUS(x[0], x[3]), 7));
        x[2] = XOR(x[2], ROTATE(PLUS(x[1], x[0]), 9));
        x[3] = XOR(x[3], ROTATE(PLUS(x[2], x[1]), 13));
        x[0] = XOR(x[0], ROTATE(PLUS(x[3], x[2]), 18));
        x[6] = XOR(x[6], ROTATE(PLUS(x[5], x[4]), 7));
        x[7] = XOR(x[7], ROTATE(PLUS(x[6], x[5]), 9));
        x[4] = XOR(x[4], ROTATE(PLUS(x[7], x[6]), 13));
        x[5] = XOR(x[5], ROTATE(PLUS(x[4], x[7]), 18));
        x[11] = XOR(x[11], ROTATE(PLUS(x[10], x[9]), 7));
        x[8] = XOR(x[8], ROTATE(PLUS(x[11], x[10]), 9));
        x[9] = XOR(x[9], ROTATE(PLUS(x[8], x[11]), 13));
        x[10] = XOR(x[10], ROTATE(PLUS(x[9], x[8]), 18));
        x[12] = XOR(x[12], ROTATE(PLUS(x[15], x[14]), 7));
        x[13] = XOR(x[13], ROTATE(PLUS(x[12], x[15]), 9));
        x[14] = XOR(x[14], ROTATE(PLUS(x[13], x[12]), 13));
        x[15] = XOR(x[15], ROTATE(PLUS(x[14], x[13]), 18));

    for i in range(len(input)):
        x[i] = PLUS(x[i], input[i])
    return little16_i32.pack(*x)


# --------------------------- 32-bit ops -------------------------------

def trunc32(w):
    """ Return the bottom 32 bits of w as a Python int.
        This creates longs temporarily, but returns an int. """
    w = int((w & 0x7fffFFFF) | -(w & 0x80000000))
    assert type(w) == int
    return w


def add32(a, b):
    """ Add two 32-bit words discarding carry above 32nd bit,
        and without creating a Python long.
        Timing shouldn't vary.
    """
    lo = (a & 0xFFFF) + (b & 0xFFFF)
    hi = (a >> 16) + (b >> 16) + (lo >> 16)
    return (-(hi & 0x8000) | (hi & 0x7FFF)) << 16 | (lo & 0xFFFF)


def rot32(w, nLeft):
    """ Rotate 32-bit word left by nLeft or right by -nLeft
        without creating a Python long.
        Timing depends on nLeft but not on w.
    """
    nLeft &= 31  # which makes nLeft >= 0
    if nLeft == 0:
        return w

    # Note: now 1 <= nLeft <= 31.
    #     RRRsLLLLLL   There are nLeft RRR's, (31-nLeft) LLLLLL's,
    # =>  sLLLLLLRRR   and one s which becomes the sign bit.
    RRR = (((w >> 1) & 0x7fffFFFF) >> (31 - nLeft))
    sLLLLLL = -((1 << (31 - nLeft)) & w) | (0x7fffFFFF >> nLeft) & w
    return RRR | (sLLLLLL << nLeft)


