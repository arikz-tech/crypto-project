import socket
import threading
import pickle

from algorithms import mceliece
from algorithms import elgamal
from algorithms import camellia


HEADER = 64
PORT = 5051
IP = socket.gethostbyname(socket.gethostname())
ADDRESS = (IP, PORT)
FORMAT = 'utf-8'

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
mceliece_keys = mceliece.KeyGeneration(3)
public_key = mceliece_keys.GPrime
public_key_pickled = pickle.dumps(public_key)


def handle_client(connection, address):
    print(f"[Alice]: connected")
    connection.send(public_key_pickled)

    connected = True
    while connected:
        message_len = connection.recv(HEADER).decode(FORMAT)
        if message_len:
            message_len = int(message_len)
            message_bytes = connection.recv(message_len)
            message = pickle.loads(message_bytes)

            # The whole message sent by alice
            a1, q1, ya1, k1, m1, s11, s21, a2, q2, ya2, k2, m2, s12, s22, original_iv, cipher, cipher_key = message

            # Verify digital signature by Elgamal algorithm, verifying the encrypted message and encrypted key
            digital_signature_encrypted_message = elgamal.elgamal_verify_signature(a1, q1, ya1, m1, s11, s21)
            print("[Bob]: Encrypted message digital signatures is verified")
            digital_signature_encrypted_key = elgamal.elgamal_verify_signature(a2, q2, ya2, m2, s12, s22)
            print("[Bob]: Encrypted key digital signatures is verified")
            verified = digital_signature_encrypted_message and digital_signature_encrypted_key

            if verified:
                print("[Bob]: Total digital signatures is verified")
                key = mceliece.decrypt_secret_key(cipher_key, mceliece_keys.S, mceliece_keys.P, mceliece_keys.H)
                print("[Bob]: Key is decrypted by mceliece algorithm")
                print(f"[Bob]: The encrypted sent message:{decode_message(cipher)}")
                message = camellia.ofb_decryption(cipher, key.encode(FORMAT), original_iv)
                print(f"[Bob]: The decrypted message: {message.decode(FORMAT)}")
            else:
                print("[Bob]: The message failed digital signature")


def start():
    server.listen()
    print(f"[Bob]: listening...")
    while True:
        connection, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()


def decode_message(cipher):
    decoded_message = ""
    for block in cipher:
        decoded_message += block.decode("utf-8", errors="ignore")
    return decoded_message


print(f"[Bob]: starting...")
start()
