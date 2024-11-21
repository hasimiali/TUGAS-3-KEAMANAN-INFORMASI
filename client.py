import socket
from rsa_utils import encrypt_rsa
from des_constants import *


def start_client(plaintext: str, des_key: str):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 12345))

    # Receive public key from the server
    public_key_data = client_socket.recv(1024).decode()
    e, n = map(int, public_key_data.split(","))
    server_public_key = (e, n)
    print("Received server public key:", server_public_key)

    # Encrypt DES key using RSA public key
    des_key_int = int(des_key, 16)  # Convert hex string to int
    encrypted_key = encrypt_rsa(server_public_key, des_key_int)
    client_socket.send(str(encrypted_key).encode())
    print("Sent encrypted DES Key to server.")

    # Send plaintext to the server
    client_socket.send(plaintext.encode())
    print("Sent plaintext to server:", plaintext)

    # Receive ciphertext from the server
    encrypted_text = client_socket.recv(1024).decode()
    print("Received encrypted text from server:", encrypted_text)

    client_socket.close()


if __name__ == "__main__":
    plaintext = "halo ali"  # 8 characters for 64-bit block
    des_key = "133457799BBCDFF1"  # DES Key (in hex format)
    start_client(plaintext, des_key)
