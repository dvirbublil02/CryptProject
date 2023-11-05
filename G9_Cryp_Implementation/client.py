import socket
import pickle
import ECDSA
import mceliece
from Salsa20 import Salsa20
import const as cn
import common as cm


SERVER_IP = socket.gethostbyname(socket.gethostname())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


ADDRESS = (SERVER_IP, cn.PORT)
client.connect(ADDRESS)
print("Connected")

salsa20_key = Salsa20.generate_pseudo_random_key()


def start():
    print("Alice: sending session key...")
    send_encrypted_session_key()
    input_request = "Enter o(override)/r(read)/d(delete), followed by index you want to " \
                    "select (if you want to override add the override string as well):\n "

    while True:
        print()
        request_msg = input(input_request)
        msg = cm.encrypt_message(client, request_msg, salsa20_key)
        print("Encrypt message: " + msg)
        if request_msg.lower() == 'close':
            break
        # server response
        msg = cm.decrypt_message(client, salsa20_key)
        print("Decrypt Server response: " + msg)


def send_encrypted_session_key():
    public_key_message = client.recv(cn.PICKLE_HEADER)
    # Unpickle from byte stream format
    sign_encrypted_msg, C, P, n, public_key = pickle.loads(public_key_message)
    verify_msg = ECDSA.verify(str(public_key), C, P, n, sign_encrypted_msg)

    if verify_msg:
        cipher_key = mceliece.encrypt_secret_key(salsa20_key, public_key)
        C = ECDSA.CurveOverFp(0, 1, 7, 729787)
        # create a base point using ECDSA
        P = ECDSA.Point(1, 3)
        n = C.order(P)
        key_pair = ECDSA.generate_keypair(C, P, n)
        # sign encrypted message
        sign_encrypted_msg = ECDSA.sign(cipher_key, C, P, n, key_pair)
        message_packet = [sign_encrypted_msg, C, P, n, cipher_key]
        cm.send(client, pickle.dumps(message_packet))


start()
