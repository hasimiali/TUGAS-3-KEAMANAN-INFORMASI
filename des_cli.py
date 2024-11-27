from des_constants import *

import string
import random

def generate_random_key():
    # Menghasilkan kunci acak 16 karakter dari 0-9 dan a-f
    key = ''.join(random.choices('0123456789abcdef', k=16))
    return key

def str_to_bin(user_input):
    # Mengonversi string ke dalam bentuk biner
    binary_representation = ''
    
    for char in user_input:
        # Mendapatkan nilai ASCII karakter dan mengonversinya ke biner
        binary_char = format(ord(char), '08b')
        binary_representation += binary_char
        binary_representation = binary_representation[:64]
    
    # Menambah atau memotong representasi biner menjadi 64 bit
    binary_representation = binary_representation[:64].ljust(64, '0')
    
    return binary_representation

def binary_to_ascii(binary_str):
    # Mengonversi biner ke string ASCII
    ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
    return ascii_str

def binary_to_hex(binary_str):
    # Mengonversi biner ke bentuk hexadecimal
    hex_str = hex(int(binary_str, 2))[2:].zfill(16)
    return hex_str

def hex_to_binary(hex_str):
    # Mengonversi hexadecimal ke biner
    binary_str = bin(int(hex_str, 16))[2:].zfill(64)
    return binary_str

def ip_on_binary_rep(binary_representation):
    # Melakukan permutasi pada representasi biner menggunakan tabel IP
    ip_result = [None] * 64
    
    for i in range(64):
        ip_result[i] = binary_representation[ip_table[i] - 1]

    # Mengonversi hasilnya kembali ke string untuk visualisasi
    ip_result_str = ''.join(ip_result)
    
    return ip_result_str

def key_in_binary_conv(key):
    # Mengonversi kunci menjadi biner 64-bit
    binary_representation_key = ''
    
    for char in key:
        # Mengonversi karakter ke biner dan menggabungkannya untuk membentuk string biner 64-bit
        binary_key = format(ord(char), '08b') 
        binary_representation_key += binary_key
    
    # Menambah ke 64 bit jika diperlukan
    while len(binary_representation_key) < 64:
        binary_representation_key = '0' + binary_representation_key
    
    return binary_representation_key

def generate_round_keys(key):
    # Menghasilkan kunci-kunci untuk setiap ronde
    binary_representation_key = key_in_binary_conv(key)
    pc1_key_str = ''.join(binary_representation_key[bit - 1] for bit in pc1_table)

    # Memisahkan kunci 56-bit menjadi dua bagian 28-bit
    c0 = pc1_key_str[:28]
    d0 = pc1_key_str[28:]
    round_keys = []
    for round_num in range(16):
        # Melakukan pergeseran sirkular kiri pada C dan D
        c0 = c0[shift_schedule[round_num]:] + c0[:shift_schedule[round_num]]
        d0 = d0[shift_schedule[round_num]:] + d0[:shift_schedule[round_num]]
        # Menggabungkan C dan D
        cd_concatenated = c0 + d0

        # Melakukan permutasi PC2
        round_key = ''.join(cd_concatenated[bit - 1] for bit in pc2_table)

        # Menyimpan kunci untuk ronde tersebut
        round_keys.append(round_key)
    return round_keys

def encryption(user_input, key):
    # Mengonversi input pengguna ke biner
    binary_rep_of_input = str_to_bin(user_input)
    # Menghasilkan kunci-kunci untuk setiap ronde
    round_keys = generate_round_keys(key)

    # Melakukan permutasi awal pada input
    ip_result_str = ip_on_binary_rep(binary_rep_of_input)

    # Membagi hasil permutasi awal menjadi dua bagian
    lpt = ip_result_str[:32]
    rpt = ip_result_str[32:]

    # Melakukan proses enkripsi selama 16 ronde
    for round_num in range(16):
        # Melakukan ekspansi (32 bit ke 48 bit)
        expanded_result = [rpt[i - 1] for i in e_box_table]

        # Mengonversi hasil ekspansi ke string untuk visualisasi
        expanded_result_str = ''.join(expanded_result)

        # Kunci ronde untuk ronde ini
        round_key_str = round_keys[round_num]

        # Melakukan XOR antara hasil ekspansi dan kunci ronde
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

        # Memecah hasil XOR menjadi 8 grup 6-bit
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

        # Menginisialisasi string hasil substitusi S-box
        s_box_substituted = ''

        # Melakukan substitusi S-box untuk setiap grup 6-bit
        for i in range(8):
            # Menyusun bit baris dan kolom
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)

            # Mencari nilai S-box
            s_box_value = s_boxes[i][row_bits][col_bits]
            
            # Mengonversi nilai S-box menjadi string biner 4-bit dan menambahkannya ke hasil
            s_box_substituted += format(s_box_value, '04b')

        # Melakukan permutasi P pada hasil
        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]

        # Mengonversi hasilnya kembali ke string untuk visualisasi
        # p_box_result_str = ''.join(p_box_result)

        # Mengonversi LPT menjadi list bit untuk operasi XOR
        lpt_list = list(lpt)

        # Melakukan operasi XOR
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        # Mengonversi hasil XOR kembali ke string untuk visualisasi
        new_rpt_str = ''.join(new_rpt)

        # Memperbarui LPT dan RPT untuk ronde berikutnya
        lpt = rpt
        rpt = new_rpt_str

    # Setelah ronde terakhir, membalikkan swap terakhir
    final_result = rpt + lpt

    # Melakukan permutasi terakhir (IP-1)
    final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

    # Mengonversi hasilnya kembali ke string untuk visualisasi
    final_cipher_str = ''.join(final_cipher)

    # Mengonversi cipher biner ke ASCII
    final_cipher_ascii = binary_to_ascii(final_cipher_str)
    final_cipher_hex = binary_to_hex(final_cipher_str)
    
    return final_cipher_hex

# dekripsi untuk mengembalikan cipher ke teks asli

def decryption(final_cipher_hex, key):
    # Mengonversi cipher hexadecimal ke biner
    final_cipher = hex_to_binary(final_cipher_hex)
    
    # Menghasilkan kunci-kunci untuk setiap ronde
    round_keys = generate_round_keys(key)
    
    # Melakukan permutasi awal
    ip_dec_result_str = ip_on_binary_rep(final_cipher)
    
    lpt = ip_dec_result_str[:32]
    rpt = ip_dec_result_str[32:]

    for round_num in range(16):
        # Melakukan ekspansi (32 bit ke 48 bit)
        expanded_result = [rpt[i - 1] for i in e_box_table]
    
        # Mengonversi hasil ekspansi ke string untuk visualisasi
        expanded_result_str = ''.join(expanded_result)
    
        # Kunci ronde untuk ronde ini
        round_key_str = round_keys[15-round_num]
    
        # Melakukan XOR antara hasil ekspansi dan kunci ronde 
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))
    
        # Memecah hasil XOR menjadi 8 grup 6-bit
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]
    
        # Menginisialisasi string hasil substitusi S-box
        s_box_substituted = ''
    
        # Melakukan substitusi S-box untuk setiap grup 6-bit
        for i in range(8):
            # Menyusun bit baris dan kolom
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)
    
            # Mencari nilai S-box
            s_box_value = s_boxes[i][row_bits][col_bits]
            
            # Mengonversi nilai S-box menjadi string biner 4-bit dan menambahkannya ke hasil
            s_box_substituted += format(s_box_value, '04b')
    
        # Melakukan permutasi P pada hasil
        p_box_result = [s_box_substituted[i - 1] for i in p_box_table]
    
        # Mengonversi LPT menjadi list bit untuk operasi XOR
        lpt_list = list(lpt)
    
        # Melakukan operasi XOR
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]
    
        # Mengonversi hasil XOR kembali ke string untuk visualisasi
        new_rpt_str = ''.join(new_rpt)
    
        # Memperbarui LPT dan RPT untuk ronde berikutnya
        lpt = rpt
        rpt = new_rpt_str

    # Setelah ronde terakhir, membalikkan swap terakhir
    final_result = rpt + lpt

    # Melakukan permutasi terakhir (IP-1)
    final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]
    
    # Mengonversi hasilnya kembali ke string untuk visualisasi
    final_cipher_str = ''.join(final_cipher)

    # Mengonversi cipher biner ke ASCII
    final_cipher_ascii = binary_to_ascii(final_cipher_str)
    
    return final_cipher_ascii


def pad_input(user_input):
    # Menambahkan padding berupa spasi hingga panjang input menjadi kelipatan 8
    while len(user_input) % 8 != 0:
        user_input += ' '  # Menambahkan spasi sebagai padding
    return user_input

def encryption_large_text(user_input, key):
    # Mengenskripsi teks panjang dengan membaginya menjadi blok 8 karakter
    user_input = pad_input(user_input)  
    encrypted_text = ""  
    for i in range(0, len(user_input), 8):  # Memproses input per blok 8 karakter
        block = user_input[i:i+8] 
        encrypted_block = encryption(block, key)  
        encrypted_text += encrypted_block  
    return encrypted_text

def decryption_large_text(encrypted_text, key):
    # Mendekripsi teks panjang dengan membaginya menjadi blok 16 karakter (ukuran enkripsi)
    decrypted_text = "" 
    for i in range(0, len(encrypted_text), 16):  # Memproses teks terenkripsi per blok 16 karakter
        block = encrypted_text[i:i+16]  
        decrypted_block = decryption(block, key) 
        decrypted_text += decrypted_block 
    return decrypted_text.strip()  # Menghapus padding yang ditambahkan sebelumnya
