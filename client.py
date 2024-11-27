import socket
from des_cli import *
from rsa import *

# Fungsi untuk mendaftarkan public key ke Public Key Authority (PKA)
def register_public_key(identifier, public_key):
    # Membuat koneksi ke server PKA
    pka_socket = socket.socket()
    pka_socket.connect(("127.0.0.1", 7000))  # Terhubung ke server PKA di port 7000
    e, n = public_key
    # Mengirim permintaan registrasi public key dengan identifier
    pka_socket.send(f"REGISTER {identifier} {e} {n}".encode())
    response = pka_socket.recv(1024).decode()  # Menerima respons dari server
    print(response)  # Menampilkan hasil respons
    pka_socket.close()  # Menutup koneksi ke PKA

# Fungsi untuk mengambil public key dari Public Key Authority (PKA)
def retrieve_public_key(identifier):
    # Membuat koneksi ke server PKA
    pka_socket = socket.socket()
    pka_socket.connect(("127.0.0.1", 7000))  # Terhubung ke server PKA
    # Mengirim permintaan untuk mendapatkan public key
    pka_socket.send(f"GET {identifier}".encode())
    response = pka_socket.recv(1024).decode()  # Menerima respons dari server
    pka_socket.close()  # Menutup koneksi ke PKA
    if response == "Public Key Not Found":
        # Jika public key tidak ditemukan, lemparkan exception
        raise Exception("Tidak ada public key yang ditemukan di PKA untuk identifier yang diberikan")
    e, n = map(int, response.split())  # Memproses respons menjadi pasangan public key
    return (e, n)

# Fungsi utama untuk proses komunikasi klien
def client_process():
    host = socket.gethostname()  # Mendapatkan nama host
    port = 5000  # Port komunikasi dengan server
    des_encrypt = encryption_large_text  # Alias untuk fungsi enkripsi DES
    des_decrypt = decryption_large_text  # Alias untuk fungsi dekripsi DES
    generate_key = generate_random_key  # Alias untuk fungsi pembuatan kunci DES

    # Membuat pasangan kunci RSA untuk klien
    public_key, private_key = generate_rsa_keys()
    print("Public Key RSA Klien:", public_key)

    # Mendaftarkan public key klien ke PKA
    register_public_key("CLIENT", public_key)

    # Mengambil public key server dari PKA
    server_public_key = retrieve_public_key("SERVER")
    print("Public Key RSA Server:", server_public_key)
    print("\n")

    # Membuat koneksi ke server
    client_socket = socket.socket()
    client_socket.connect((host, port))

    while True:
        # Membuat kunci DES baru untuk sesi komunikasi
        session_des_key = generate_key()
        print("Kunci DES Baru untuk Enkripsi Pesan:", session_des_key)

        # Mengenkripsi kunci DES menggunakan public key RSA server
        encrypted_session_key = rsa_encrypt(server_public_key, session_des_key)
        print("Kunci DES yang Dienkripsi untuk Transmisi:", encrypted_session_key)

        # Input pesan plaintext dari pengguna
        message = input("Masukkan pesan untuk server: ")
        if message.lower().strip() == "bye":  # Keluar dari loop jika pengguna mengetik "bye"
            break

        # Mengenkripsi pesan menggunakan kunci DES yang dihasilkan
        encrypted_message = des_encrypt(message, session_des_key)

        # Mengirim kunci DES terenkripsi dan pesan terenkripsi ke server
        client_socket.send(f"{encrypted_session_key}|{encrypted_message}".encode())
        print("Pesan Terenkripsi Dikirim ke Server:", encrypted_message)
        print("\n")

        # Menerima respons terenkripsi dari server
        response = client_socket.recv(1024).decode()
        encrypted_key_from_server, encrypted_response_message = response.split('|')

        # Mendekripsi kunci DES yang dikirim oleh server
        response_key = rsa_decrypt(private_key, eval(encrypted_key_from_server))
        print("Kunci DES yang Didekripsi dari Server:", response_key)

        # Mendekripsi pesan respons dari server
        decrypted_response = des_decrypt(encrypted_response_message, response_key)
        print("Respons Terenkripsi dari Server:", encrypted_response_message)
        print("Respons Didekripsi dari Server:", decrypted_response)
        print("\n")

    # Menutup koneksi ke server
    client_socket.close()

if __name__ == '__main__':
    client_process()
