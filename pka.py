import socket
import threading

# Kamus untuk menyimpan kunci publik yang terdaftar
public_keys = {}

def handle_client(conn, addr):
    """
    Menangani permintaan klien untuk mendaftarkan atau mengambil kunci publik.
    """
    while True:
        # Menerima data dari klien
        data = conn.recv(1024).decode()
        if not data:
            break

        # Memparse perintah yang diterima
        command, identifier, *key_data = data.split(' ')
        if command == "REGISTER":
            # Mendaftarkan kunci publik dengan identifier yang diberikan
            public_keys[identifier] = ' '.join(key_data)
            conn.send("Kunci Publik Terdaftar".encode())
        elif command == "GET":
            # Mengambil kunci publik untuk identifier yang diminta
            key = public_keys.get(identifier, "Kunci Publik Tidak Ditemukan")
            conn.send(key.encode())

    # Menutup koneksi setelah menangani klien
    conn.close()

def start_pka():
    """
    Memulai server Public Key Authority (PKA).
    """
    host = "127.0.0.1"
    port = 7000
    server = socket.socket()
    server.bind((host, port))
    server.listen(5)  # Memungkinkan hingga 5 koneksi dalam antrean
    print("Server Public Key Authority (PKA) sedang berjalan...")

    while True:
        # Menerima koneksi klien yang masuk
        conn, addr = server.accept()
        print(f"Koneksi terjalin dengan: {addr}")
        # Menangani setiap klien dalam thread terpisah
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_pka()
