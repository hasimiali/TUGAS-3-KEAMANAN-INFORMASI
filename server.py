import socket
from des_cli import *
from rsa import *

def register_server_public_key(identifier, public_key):
    pka_connection = socket.socket()
    pka_connection.connect(("127.0.0.1", 7000))
    e, n = public_key
    pka_connection.send(f"REGISTER {identifier} {e} {n}".encode())
    server_response = pka_connection.recv(1024).decode()
    print(server_response)
    pka_connection.close()

def retrieve_public_key(identifier):
    pka_connection = socket.socket()
    pka_connection.connect(("127.0.0.1", 7000))
    pka_connection.send(f"GET {identifier}".encode())
    server_response = pka_connection.recv(1024).decode()
    pka_connection.close()
    if server_response == "Public Key Not Found":
        raise Exception("Public Key Not Found in PKA")
    e, n = map(int, server_response.split())
    return (e, n)

def start_server():
    host = socket.gethostname()
    port = 5000
    encryption_function = encryption_large_text
    decryption_function = decryption_large_text
    generate_key = generate_random_key

    # Membuat pasangan kunci RSA
    public_key, private_key = generate_rsa_keys()
    print("Server RSA Public Key:", public_key)

    # Mendaftarkan kunci publik server ke PKA
    register_server_public_key("SERVER", public_key)

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    conn, address = server_socket.accept()
    print("Koneksi dari:", address)

    # Mengambil kunci publik klien dari PKA
    client_public_key = retrieve_public_key("CLIENT")
    print("Client Public Key:", client_public_key)
    print("\n")

    while True:
        # Langkah 1: Menerima kunci DES yang terenkripsi dan pesan dari klien
        incoming_data = conn.recv(1024).decode()
        if not incoming_data:
            break
        encrypted_key, encrypted_message = incoming_data.split('|')

        # Mendekripsi kunci DES untuk pesan
        des_key = rsa_decrypt(private_key, eval(encrypted_key))
        print("Kunci DES yang didekripsi untuk pesan:", des_key)

        # Mendekripsi pesan yang sesungguhnya menggunakan kunci DES yang didekripsi
        decrypted_message = decryption_function(encrypted_message, des_key)
        print("Pesan Klien yang Terenkripsi:", encrypted_message)
        print("Pesan Klien yang Didekripsi:", decrypted_message)
        print("\n")

        # Langkah 2: Membuat kunci DES baru untuk respons server
        response_des_key = generate_key()
        print("Kunci DES yang Dihasilkan untuk Respons:", response_des_key)

        # Mengenkripsi kunci DES baru dengan kunci publik klien
        encrypted_response_key = rsa_encrypt(client_public_key, response_des_key)

        # Meminta respons dari server dan mengenkripsi menggunakan kunci DES baru
        server_response = input("Respons Server: ")
        if server_response.lower().strip() == "bye":
            break
        encrypted_server_response = encryption_function(server_response, response_des_key)

        # Mengirim kunci DES yang terenkripsi dan respons ke klien
        conn.send(f"{encrypted_response_key}|{encrypted_server_response}".encode())
        print("Respons yang Terenkripsi:", encrypted_server_response)
        print("\n")

    conn.close()

if __name__ == '__main__':
    start_server()
