import socket
import pickle
from algorithms import elgamal
from algorithms import camellia
from algorithms import mceliece

HEADER = 64
PICKLE_HEADER = 4096
PORT = 5051
FORMAT = 'utf-8'
SERVER_IP = "10.0.0.16"
ADDRESS = (SERVER_IP, PORT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)


def send(message):
    message_length = len(message)
    message_length_byte = str(message_length).encode(FORMAT)
    message_padding_byte = b' ' * (HEADER - len(message_length_byte))
    message_length_byte = message_length_byte + message_padding_byte

    client.send(message_length_byte)
    client.send(message)


def start():
    print("[Alice]: starting...")
    public_key_message = client.recv(PICKLE_HEADER)
    public_key = pickle.loads(public_key_message)

    while True:
        message = input("Enter message you want to send ")
        key = ""

        while len(key) != 16:
            key = input("Enter encryption key(16 letters) you want to use: ")
            if len(key) != 16:
                print("Invalid key")

        # Encrypt the message by using Camellia algorithm, on mode OFB
        original_iv, cipher = camellia.ofb_encryption(message.encode(FORMAT), key.encode(FORMAT))

        # Encrypt the secret key by using Mceliece algorithm
        cipher_key = mceliece.encrypt_secret_key(key, public_key)

        # Sign on the encrypted message by using Elgamal algorithm
        a1, q1, ya1, k1, m1, s11, s21 = elgamal.elgamal_digital_sign(cipher)

        # Sign on the encrypted key by using Elgamal algorithm
        a2, q2, ya2, k2, m2, s12, s22 = elgamal.elgamal_digital_sign(cipher_key)

        message_packet = [a1, q1, ya1, k1, m1, s11, s21, a2, q2, ya2, k2, m2, s12, s22, original_iv, cipher, cipher_key]
        message_packet = pickle.dumps(message_packet)
        send(message_packet)


start()
