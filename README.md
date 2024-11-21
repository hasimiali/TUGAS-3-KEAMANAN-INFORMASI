# TUGAS-2-KEAMANAN-INFORMASI

# Implementasi RSA untuk Pengiriman Kunci DES dan DES untuk Enkripsi Data

## Deskripsi Proyek
Proyek ini mengimplementasikan pengiriman kunci DES menggunakan algoritma RSA dan enkripsi data menggunakan DES. Server dan klien berkomunikasi menggunakan protokol socket, di mana kunci DES dienkripsi dengan RSA sebelum dikirimkan untuk meningkatkan keamanan. Program ini juga memastikan pembagian tugas antar individu dicatat secara transparan.

---

## Cara Kerja
1. **Key Exchange**:
   - Klien mendapatkan public key RSA dari server.
   - Klien mengenkripsi kunci DES menggunakan public key RSA dan mengirimkannya ke server.
   - Server mendekripsi kunci DES menggunakan private key RSA.

2. **DES Encryption**:
   - Server mengenkripsi plaintext menggunakan DES dan mengirimkan ciphertext kembali ke klien.

3. **Protokol Komunikasi**:
   - Public key RSA dikirimkan dari server ke klien secara otomatis.
   - Data dikirimkan melalui socket dalam format terpisah antara kunci DES dan plaintext.

---

## Teknologi yang Digunakan
- **Python**:
  - Socket programming untuk komunikasi antara server dan klien.
  - RSA dan DES diimplementasikan tanpa pustaka eksternal untuk memahami algoritma dasar.
- **GitHub**: 
  - Digunakan untuk version control, termasuk commit individu untuk evaluasi.

---

### **Detail Pekerjaan**
1. **Ali Hasyimi Assegaf**:
   - Implementasi fungsi `generate_keypair`, `encrypt_rsa`, `decrypt_rsa` untuk RSA.
   - Menyediakan mekanisme enkripsi dan dekripsi kunci DES.
   - Pembuatan `server.py` dan `client.py` untuk komunikasi antar sistem.
   - Menangani pengiriman public key RSA dan data DES secara terpisah.
   - Menyusun dokumentasi proyek pada `README.md`.

