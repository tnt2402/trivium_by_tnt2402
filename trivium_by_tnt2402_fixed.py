import binascii
import secrets
from collections import deque
from itertools import repeat
import sys
import argparse


class Trivium:
    def __init__(self, key, iv):
        """in the beginning we need to transform the key as well as the IV.
        Afterwards we initialize the state."""
        self.state = None
        self.counter = 0
        self.key = key
        self.iv = iv
        '''
		<Key and IV setup>
		288-bit Initialize state
			(s 1 , s2 , . . . , s93 ) <- (K1, . . . , K80 , 0, . . . , 0)
			(s 94, s95 , . . . , s177) <- (IV1 , . . . , IV80 , 0, . . . , 0)
			(s 178 , s279 , . . . , s288) <- (0, . . . , 0, 1, 1, 1)
        '''
		# bit 1 -> 93
        init_list = list(map(int, list(self.key)))
        init_list += list(repeat(0, 13))
		# bit 94 -> 177 
        init_list += list(map(int, list(self.iv)))
        init_list += list(repeat(0, 4))
		# bit 178 -> 288
        init_list += list(repeat(0, 108))
        init_list += list([1, 1, 1])
        self.state = deque(init_list)

        # Do 4 full cycles, drop output
        for i in range(4 * 288):
            self._gen_keystream()

    def keystream_1(self, number):
        keystream = []
        for i in range(number):
            keystream.append(self._gen_keystream())
        return bits_to_hex(keystream)

    def _gen_keystream(self):
        '''
		<Key stream generation>
		for i = 1 to N do
			t1 <- s66 + s93
			t2 <- s162 + s177
			t3 <- s243 + s288
			zi <- t1 + t2 + t3
			t1 <- t1 + s91 · s92 + s171
			t2 <- t2 + s175 · s176 + s264
			t3 <- t3 + s286 · s287 + s69
			(s1 , s2 , . . . , s93 ) <- (t3, s1 , . . . , s92)
			(s94 , s95 , . . . , s177 ) <- (t1 , s94, . . . , s176 )
			(s178 , s279 , . . . , s288) <- (t2 , s178 , . . . , s287 )
		end for
		'''
        t_1 = self.state[65] ^ self.state[92]
        t_2 = self.state[161] ^ self.state[176]
        t_3 = self.state[242] ^ self.state[287]

        z = t_1 ^ t_2 ^ t_3

        t_1 = t_1 ^ self.state[90] & self.state[91] ^ self.state[170]
        t_2 = t_2 ^ self.state[174] & self.state[175] ^ self.state[263]
        t_3 = t_3 ^ self.state[285] & self.state[286] ^ self.state[68]

        self.state.rotate() #1 positive rotation

        self.state[0] = t_3
        self.state[93] = t_1
        self.state[177] = t_2

        return z

    def encrypt(self, message, keystream):
        keystream = _hex_to_bytes(keystream)
        buffer = bytearray()
        for i in range(len(keystream)):
            buffer.append(message[i] ^ keystream[i] & 0xff)
        return buffer

    def decrypt(self, cipher, keystream):
        keystream = _hex_to_bytes(keystream)
        buffer = bytearray()
        for i in range(len(keystream)):
            buffer.append(cipher[i] ^ keystream[i] & 0xff)
        return buffer.decode()

def _hex_to_bytes(s):
    return [_allbytes[s[i:i+2].upper()] for i in range(0, len(s), 2)]

def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)]) for i in range(0, len(b), 8)])

def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s) for i in range(8)]

_allbytes = dict([("%02X" % i, i) for i in range(256)])


def get_random_bits(length):
    randbits = secrets.randbits(length)
    randstring = '{0:080b}'.format(randbits)
    return bytearray(map(int ,randstring))


def get_bytes_from_file(filename):
    return open(filename, "rb").read()

def encrypt(input, output):
    key = get_random_bits(80)
    iv = get_random_bits(80)
    plain = get_bytes_from_file(input)
    print("[+] Plain: ", plain)
    trivium = Trivium(key, iv)
    keystream = trivium.keystream_1(len(plain) * 8)
    print("[+] IV in hex:  {}".format(bits_to_hex(iv)))
    print("[+] Key in hex: {}".format(bits_to_hex(key)))
    print("[-] Keystream in hex: {}".format(keystream))
    cipher = trivium.encrypt(plain, keystream)
    print("[-] Cipher: {}".format(cipher.hex()))
    print(cipher)
    with open(output, "wb") as output_file:
        # 80 first bits of the output file is iv
        output_file.write(iv)
        output_file.write(cipher)

def decrypt(input, output, key):
    with open(input, "rb") as input_file:
        #80 first bits of the input file is iv 
        iv = bytearray(input_file.read(80))
        #the rest is cipher
        cipher = bytes(input_file.read())
    print("[+] Cipher in bytes: ", cipher)
    trivium = Trivium(key, iv)
    keystream = trivium.keystream_1(len(cipher) * 8)
    print("[+] IV in hex:  {}".format(bits_to_hex(iv)))
    print("[+] Key in hex: {}".format(bits_to_hex(key)))
    print("[-] Keystream in hex: {}".format(keystream))
    plain = trivium.decrypt(cipher, keystream)
    print("[-] Plain: {}".format(plain))
    if (output):
        with open(output, "wb") as output_file:
            output_file.write(plain)

    
def main():
    parser = argparse.ArgumentParser(description='Decryption or encryption using Trivium stream cipher.', epilog="Made by tnt2402")
    parser.add_argument('-m', '--mode', type=str, choices=['e', 'd'], help='Choose mode: e for encryption or d for decryption')
    parser.add_argument('-k', '--key', action='store', dest='key', type=str, help='An 80 bit key')
    parser.add_argument('M', help='Ciphertext file or plaintext file')
    parser.add_argument('-o', action='store', dest='out', type=str, help='Output file')

    argv = parser.parse_args()
    mode = argv.mode
    if (mode == "e"): 
        input = argv.M
        output = argv.out
        encrypt(input, output)
    elif (mode == "d"):
        input = argv.M
        key = argv.key
        key = hex_to_bits(key)
        output = argv.out
        decrypt(input, output, key)

if __name__ == "__main__":
    main()
