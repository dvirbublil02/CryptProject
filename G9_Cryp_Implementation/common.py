"""
this is common file here we using encrypt and decreypt message 
for both of the sides (client and server)
"""
import pickle
import const as cn
from Salsa20 import Salsa20
import ECDSA

# send a given message to a given connection 
def send(connection, message):
    # Get the length of the message
    message_length = len(message)
    # Encode the message length as bytes using the FORMAT specified in the 'cn' module
    message_length_byte = str(message_length).encode(cn.FORMAT)
    # Calculate the number of padding bytes needed to meet the HEADER size from the 'cn' module
    message_padding_byte = b' ' * (cn.HEADER - len(message_length_byte))
    # Add the padding bytes to the encoded message length
    message_length_byte = message_length_byte + message_padding_byte
    # Send the encoded message length, including the padding bytes
    connection.send(message_length_byte)
    # Send the message
    connection.send(message)

#encrypt our plaintext using salsa20 and sign it using ecdsa.
def encrypt_message(connection, msg, session_key):
    #   padding for string less than 64B
    msg = msg.ljust(64, " ")
    msg = [msg[i:i + 64] for i in range(0, len(msg), 64)]
    salsa20 = Salsa20(session_key)
    cipher = []
    cipher_text = ""
    # Break to cipher blocks and appending them.
    for i in range(len(msg)):
        plain_text = msg[i].ljust(64, " ")
        cipher.append(salsa20.encryptBytes(plain_text))
        cipher_text += str(cipher[i])

    # create a curve that its equation is: y^2 = x^3 + 2x^2 + 1 over F_729787
    C = ECDSA.CurveOverFp(0, 1, 7, 729787)
    # create base point using ECDSA
    P = ECDSA.Point(1, 3)
    n = C.order(P)
    key_pair = ECDSA.generate_keypair(C, P, n)

    #   sign encrypted message
    sign_encrypted_msg = ECDSA.sign(cipher_text, C, P, n, key_pair)
    message_packet = [sign_encrypted_msg, C, P, n, cipher]
    message_packet = pickle.dumps(message_packet)
    send(connection, message_packet)
    return cipher_text

#decrypt our message using salsa20 and verify it using ecdsa.
def decrypt_message(connection, session_key):
    message_len = connection.recv(cn.HEADER).decode(cn.FORMAT)
    if message_len:
        message_len = int(message_len)
        message_bytes = connection.recv(message_len)
        message = pickle.loads(message_bytes)
        # The whole message that sent by client or server
        sign_encrypted_msg, C, P, n, cipher = message

        # Decrypting the cipher text with Salsa20.
        salsa20 = Salsa20(session_key)
        msg = ""
        cipher_text = ""
        # Decoding cipher blocks and appending them.

        for i in range(len(cipher)):
            cipher_text += str(cipher[i])
            msg += salsa20.encryptBytes(cipher[i]).decode(encoding=cn.FORMAT)

        # Verify signature on client key and msg
        verify_msg = ECDSA.verify(cipher_text, C, P, n, sign_encrypted_msg)

        if verify_msg:
            return msg
        return "massage is corrupted"
