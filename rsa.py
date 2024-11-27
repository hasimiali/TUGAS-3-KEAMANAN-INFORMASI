# Fungsi untuk menghitung Greatest Common Divisor (GCD) dari dua angka
def gcd(a, b):
    while b != 0:  # Loop sampai angka kedua menjadi nol
        a, b = b, a % b  # Perbarui 'a' dan 'b' dengan 'b' saat ini dan sisa pembagian
    return a  # Kembalikan nilai terakhir yang bukan nol sebagai GCD

# Fungsi untuk menghitung invers modular dari 'e' modulo 'phi'
def mod_inverse(e, phi):
    # Inisialisasi nilai untuk Algoritma Euclidean Diperluas
    original_phi, x0, x1 = phi, 0, 1
    while e > 1:  # Teruskan sampai 'e' menjadi 1
        q = e // phi  # Hitung hasil bagi
        e, phi = phi, e % phi  # Perbarui 'e' dan 'phi'
        x0, x1 = x1 - q * x0, x0  # Perbarui koefisien untuk 'x'
    # Pastikan hasilnya positif sebelum mengembalikan
    return x1 + original_phi if x1 < 0 else x1

# Fungsi untuk menghasilkan kunci publik dan privat RSA
def generate_rsa_keys():
    # Pilih dua angka prima besar
    p = 7919
    q = 7873
    n = p * q  # Hitung modulus untuk kunci
    phi = (p - 1) * (q - 1)  # Hitung fungsi totien Euler
    e = 65537  # Pilih eksponen publik yang umum digunakan
    d = mod_inverse(e, phi)  # Hitung eksponen privat
    # Kembalikan kunci publik dan privat sebagai tuple
    return (e, n), (d, n)

# Fungsi untuk mengenkripsi pesan teks menggunakan kunci publik RSA
def rsa_encrypt(public_key, plaintext):
    e, n = public_key  # Ambil eksponen publik dan modulus
    # Enkripsi setiap karakter dalam pesan teks dan kembalikan ciphertext sebagai daftar
    ciphertext = [pow(ord(char), e, n) for char in plaintext]
    return ciphertext

# Fungsi untuk mendekripsi pesan ciphertext menggunakan kunci privat RSA
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key  # Ambil eksponen privat dan modulus
    # Dekripsi setiap nilai dalam ciphertext dan membangun pesan teks kembali
    plaintext = ''.join([chr(pow(char, d, n)) for char in ciphertext])
    return plaintext
