import socket
from rsa_utils import generate_keypair, decrypt_rsa
from des_constants import *
from typing import List

# Generate RSA keypair
public_key, private_key = generate_keypair(1024)

print("Server Public Key:", public_key)
print("Server Private Key:", private_key)

def permute(block, table):
    return [block[x - 1] for x in table]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def left_rotate(bits, n):
    return bits[n:] + bits[:n]

def generate_keys(key):
    key = permute(key, PC1)  # 64-bit to 56-bit key
    left, right = key[:28], key[28:]
    round_keys = []
    
    for shift in LEFT_SHIFTS:
        left = left_rotate(left, shift)
        right = left_rotate(right, shift)
        round_key = permute(left + right, PC2)
        round_keys.append(round_key)
    
    return round_keys

def str_to_bin64(text: str) -> List[int]:
    bin_text = ''.join(f'{ord(char):08b}' for char in text)
    return [int(bit) for bit in bin_text.ljust(64, '0')[:64]] 

def hex_key_to_bin64(hex_key: str) -> List[int]:
    bin_key = bin(int(hex_key, 16))[2:].zfill(64)
    return [int(bit) for bit in bin_key[:64]]  

def feistel(right, subkey):
    expanded = permute(right, E)
    xored = xor(expanded, subkey)
    substituted = []
    for i in range(8):
        row = (xored[i*6] << 1) | xored[i*6 + 5]
        col = (xored[i*6 + 1] << 3) | (xored[i*6 + 2] << 2) | (xored[i*6 + 3] << 1) | xored[i*6 + 4]
        substituted.extend(bin(S_BOXES[i][row][col])[2:].zfill(4))
    return permute([int(bit) for bit in substituted], P)

def des_encrypt_decrypt(block, keys, decrypt=False):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for round_key in (reversed(keys) if decrypt else keys):
        temp_right = xor(left, feistel(right, round_key))
        left, right = right, temp_right
    return permute(right + left, IP_INV)


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 12345))
    server_socket.listen(1)
    print("Server is listening on port 12345...")

    while True:
        client_socket, addr = server_socket.accept()
        print("Connected by", addr)

        # Send public key (n) to the client
        e, n = public_key
        client_socket.send(f"{e},{n}".encode())
        print("Sent public key to client:", public_key)

        # Receive encrypted DES key
        encrypted_key = int(client_socket.recv(256).decode())
        des_key = decrypt_rsa(private_key, encrypted_key)
        des_key_hex = f"{des_key:016x}"  # Convert to hex string
        print("Decrypted DES Key:", des_key_hex)

        # Receive plaintext for encryption
        data = client_socket.recv(1024).decode()
        print("Received plaintext from client:", data)

        binary_plaintext = str_to_bin64(data)
        binary_key = hex_key_to_bin64(des_key_hex)
        round_keys = generate_keys(binary_key)
        encrypted_bin = des_encrypt_decrypt(binary_plaintext, round_keys, decrypt=False)
        encrypted_text = ''.join(map(str, encrypted_bin))

        client_socket.send(encrypted_text.encode())
        print("Sent encrypted text to client:", encrypted_text)

        client_socket.close()


if __name__ == "__main__":
    start_server()
