import numpy as np
import math


class KeyGeneration:
    # Generation of private and public key for message of size number_of_bits that will be sent

    def __init__(self):
        self.nb = 3
        self.n = 2 ** self.nb - 1
        self.k = 2 ** self.nb - self.nb - 1

        # (n,k)-linear Hamming code with a fast decoding algorithm that can correct t errors.
        # A generator matrix for this code is given by self.G

        # Generation of Hamming codes
        self.G = self.generate_g_matrix()

        # Generates an invertible matrix of size k * k
        self.S = self.generate_s_matrix()

        # Generates a permutation matrix of size n * n using the given sequence"
        self.P = self.generate_p_matrix()

        # Computes Creates the GPrime encryption k*n matrix
        self.GPrime = self.generate_g_prime_matrix()

    # Generates Generator matrix that generate code word that can be decodeable from up to t errors
    def generate_g_matrix(self):

        # Generate Hamming Code Parity-Check and Generator Matrices
        left = np.zeros((self.nb, 2 ** self.nb - 1 - self.nb)).T
        row = 0
        for j in range(2 ** self.nb):
            if j + 1 != 1:
                if (j + 1) & j != 0:
                    string_repres = np.binary_repr(j + 1)
                    column = np.zeros((len(string_repres), 1))
                    for j in range(len(string_repres)):
                        column[-j - 1] = string_repres[j]

                    # perform padding in column according to pad_width= (0, self.nb - len(string_repres))
                    column = np.pad(column, (0, self.nb - len(string_repres)), 'constant')
                    left[row] = column.T[0]
                    row += 1

        left = left.T

        # parity-check matrix block
        self.H = np.block([left, np.identity(self.nb)])

        res = np.block([np.identity(self.k), np.transpose(left)])
        return res

    # Generates an invertible matrix S
    def generate_s_matrix(self):

        S = np.random.randint(0, 2, (self.k, self.k), int)
        while np.linalg.det(S) == 0:
            S = np.random.randint(0, 2, (self.k, self.k), int)
        return S

    # Generates a random permutation of the identity matrix, P
    # P is an n × n matrix which has a single 1 in each row and column and 0's everywhere else.
    def generate_p_matrix(self):

        P = np.identity(self.n, int)
        P = P[np.random.permutation(self.n)]
        return P

    def generate_g_prime_matrix(self):
        return np.matmul(np.matmul(self.S, self.G), self.P) % 2


# When given a message, msg will be encrypted by using the public key GPrime, Errors will be added to the message the
# message msg will be encoded as a binary string of length k"
class Encryption:

    def __init__(self, msg, g_prime, t=1):
        self.GPrime = g_prime
        self.msg = msg
        (k, n) = g_prime.shape
        self.n = n
        self.k = k
        self.t = t
        self.z = self.generate_errors()
        self.encryp_msg = self.encode()

    # Generates a random n-bit vector z (binary string) containing exactly t ones (a vector of length n and weight t)
    def generate_errors(self):
        zz = np.zeros(self.n)
        list_error = np.random.choice(self.n, self.t, replace=False)
        for i in list_error:
            zz[i] = 1
        return zz

    # computes the ciphertext by multiplying by GPrime, and add random error
    def encode(self):
        self.CPrime = np.matmul(self.msg, self.GPrime) % 2
        c = (self.CPrime + self.z) % 2
        return c  # ciphertext

    def get_original_message(self):
        return self.msg

    def get_encrypted_message(self):
        return self.encryp_msg


# When given ciphertext will decode to message
class Decryption:

    def __init__(self, ciphertext, s, p, block):
        self.ciphertext = ciphertext
        self.S = s
        self.P = p
        self.block = block
        self.decrypted_message = self.decrypt()

    # Decrypt a given message msg using the private key (S,G,P)
    def decrypt(self):

        # Computes the inverse of P
        P_inverse = np.linalg.inv(self.P)

        # Computes the inverse of S
        S_inverse = np.linalg.inv(self.S)

        # Computes Cprime
        CPrime = np.matmul(self.ciphertext, P_inverse)

        # Computes msg Prime
        msgPrime = self.correct_error(CPrime)

        # Computes decrypted message
        decrypted_msg = np.matmul(msgPrime, S_inverse) % 2

        return decrypted_msg

    def correct_error(self, c_prime):
        # Calculation of parity matrix to find the error"
        parity_matrix = np.matmul(c_prime, np.transpose(self.block)) % 2

        parity_bits = np.ma.size(parity_matrix, 0)
        syndrome = 0

        # Calculation of the Syndrome (From bitstring to integer) The receiver multiplies parity_check matrix and the
        # received codeword to obtain the syndrome vector, which will indicate whether an error has occurred,
        # and if so, for which codeword bit. Performing this multiplication again"

        for j in range(parity_bits):
            syndrome += 2 ** j * parity_matrix[j]

        # In the case of no error is found, return the message
        if (int((syndrome - 1)) & int(syndrome)) == 0:
            return c_prime[0:(c_prime.size - parity_bits)]

        else:
            # In the case of error is detected, an error correction process will be performed
            err_msg = c_prime
            err_bit = int(syndrome - math.ceil(np.log2(syndrome)) - 1)
            if err_msg[err_bit] == 1:
                err_msg[err_bit] = 0
                return err_msg[0:(c_prime.size - parity_bits)]
            elif err_msg[err_bit] == 0:
                err_msg[err_bit] = 1
                return err_msg[0:(c_prime.size - parity_bits)]

    def get_decrypted_message(self):
        return self.decrypted_message


# ################### Encrypt String ############################

def char_to_binary(char):
    b_array = []
    binary = bin(ord(char))
    binary = binary[2:]
    for bit in binary:
        if bit == "1":
            b_array.append(1)
        else:
            b_array.append(0)

    while len(b_array) < 7:
        b_array.insert(0, 0)

    return b_array


def binary_to_char(b_arr):
    b_str = ""
    for bit in b_arr:
        if bit == 1.0:
            b_str += "1"
        else:
            b_str += "0"

    return chr(int(b_str[:8], 2))


def mceliece_encrypt_char(char, public_key):
    binary = char_to_binary(char)
    higher_bit = [0] + binary[0:3]
    lower_bit = binary[3:7]

    # higher bit encryption
    higher_bit_cipher = Encryption(higher_bit, public_key).encode()
    char_higher = binary_to_char(higher_bit_cipher)

    # lower bit encryption
    lower_bit_cipher = Encryption(lower_bit, public_key).encode()
    char_lower = binary_to_char(lower_bit_cipher)

    return char_higher + char_lower


def mceliece_decrypt_char(two_char, key_s, key_p, key_block):
    # higher bit decryption
    bit_array = char_to_binary(two_char[0])
    higher_bit_array_decrypted = Decryption(bit_array, key_s, key_p, key_block)

    # # lower bit decryption
    bit_array = char_to_binary(two_char[1])
    lower_bit_array_decrypted = Decryption(bit_array, key_s, key_p, key_block)

    res = np.concatenate((higher_bit_array_decrypted.decrypt(), lower_bit_array_decrypted.decrypt()))

    return binary_to_char(res)


def encrypt_secret_key(secret_key, public_key):
    encrypted_key = ""
    for char in secret_key:
        encrypted_key += mceliece_encrypt_char(char, public_key)

    return encrypted_key


def decrypt_secret_key(cipher_secret_key, key_s, key_p, key_block):
    decrypted_key = ""
    for i in range(0, len(cipher_secret_key), 2):
        two_char = cipher_secret_key[i:i + 2]
        decrypted_key += mceliece_decrypt_char(two_char, key_s, key_p, key_block)

    return decrypted_key
