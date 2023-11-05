import socket
import threading
import pickle
import shelve
import ECDSA
import mceliece
import const as cn
import common as cm

default_data_base = {'1': 'Aviel Malayev', '2': 'Mor Ben-Haim', '3': 'Dvir Bublil', '4': 'Ran Polac'}

IP = socket.gethostbyname(socket.gethostname())
ADDRESS = (IP, cn.PORT)
#   Set a socket server.
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)

#   Generating a public key with mceliece.
mceliece_keys = mceliece.KeyGeneration()
public_key = mceliece_keys.GPrime

#when client is connected the server publish his mceliece public key after he signed it by using ECDSA.
def create_session_with_client(connection, address):
    C = ECDSA.CurveOverFp(0, 1, 7, 729787)
    # create the base point by using ECDSA
    P = ECDSA.Point(1, 3)
    n = C.order(P)
    key_pair = ECDSA.generate_keypair(C, P, n)
    # sign encrypted message
    sign_encrypted_msg = ECDSA.sign(str(public_key), C, P, n, key_pair)
    message_packet = [sign_encrypted_msg, C, P, n, public_key]
    connection.send(pickle.dumps(message_packet))
    message_len = connection.recv(cn.HEADER).decode(cn.FORMAT)
    print('session created')
    if message_len:
        message_len = int(message_len)
        message_bytes = connection.recv(message_len)
        message = pickle.loads(message_bytes)
        sign_encrypted_msg, C, P, n, cipher_key = message
        # Verify signature 
        verify_msg = ECDSA.verify(cipher_key, C, P, n, sign_encrypted_msg)
        if verify_msg:
            session_key = mceliece.decrypt_secret_key(cipher_key, mceliece_keys.S, mceliece_keys.P, mceliece_keys.H)
            handle_client(connection, session_key)
    #if the message is not verifyed or the client disconccted
    print('failed to create session')

#after the session create , all the requests (messges) will handle in this method . the session creation perform only once to client
def handle_client(connection, session_key):
    print(f"Alice: connected")
    while True:
        msg = cm.decrypt_message(connection, session_key)
        print("Decrypt message: " + msg)
        if msg.strip().lower() == 'close':
            break
        # check if it's an edit or read level of access and commit change to DB
        response_msg = check_request(msg)
        # encrypt the response:
        cm.encrypt_message(connection, response_msg, session_key)

#this method check the client request and send the suitbale response
def check_request(msg):
    # Open the shelve file containing the data_base
    shlv = shelve.open("DataBase")
    # If the shelve file does not contain the key "DataBase", set it to the default_data_base
    if not shlv.__contains__("DataBase"):
        shlv["DataBase"] = default_data_base
    # Load the data_base from the shelve file
    data_base = dict(shlv["DataBase"])
    # Get the key for the operation
    key_in_dict = msg[2]
    # Get the access level ('o' for override, 'r' for read, 'd' for delete)
    access_level = msg[0]
    if access_level == 'o':
        # Get the value to be stored in the data_base
        value = msg[3:]
        # Strip the value of any leading/trailing whitespaces
        value = ' '.join(value.split())
        # Update the data_base with the new key-value pair
        data_base[key_in_dict] = value
        # Store the updated data_base in the shelve file
        shlv["DataBase"] = data_base
        return "finished overriding"
    if access_level == 'r':
        # Try to retrieve the value associated with the key, return 'key not found in Data Base' if not found
        return data_base.get(key_in_dict, 'key not found in Data Base')
    if access_level == 'd':
        # Delete the key-value pair associated with the key, return the value and 'deleted' if key is found
        if data_base.__contains__(key_in_dict):
            msg = f"{data_base.pop(key_in_dict)} - deleted"
            shlv["DataBase"] = data_base
            return msg
        return 'key not found in Data Base'
    # Return "illegal operation" if the access_level is not one of the supported operations
    return "illegal operation"


def start():
    #server is listening 
    server.listen()
    print(f"Bob: listening...")
    while True:
        connection, address = server.accept()
        thread = threading.Thread(target=create_session_with_client, args=(connection, address))
        thread.start()


print(f"Bob: starting...")
start()
