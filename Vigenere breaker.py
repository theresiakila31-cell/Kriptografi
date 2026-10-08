import argparse
import re
import string
from collections import Counter
from math import gcd
from functools import reduce
ALPHA = string.ascii_uppercase
FREQ = {'en': [8.17, 1.49, 2.78, 4.25, 12.7, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.1, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07], 'id': [19.0, 3.0, 1.0, 3.5, 7.5, 0.3, 3.0, 2.5, 8.5, 1.0, 5.0, 3.3, 3.5, 10.0, 2.5, 2.5, 0.01, 5.0, 4.5, 5.0, 5.0, 0.1, 0.5, 0.01, 1.0, 0.1]}

def geser_huruf(ch, shift):
    base = ord('A') if ch.isupper() else ord('a')
    return chr((ord(ch) - base + shift) % 26 + base)

def vigenere(teks, kunci, mode=1):
    kunci = [ord(k) - 65 for k in kunci.upper() if k.isalpha()]
    out, i = ([], 0)
    for ch in teks:
        if ch.isalpha():
            out.append(geser_huruf(ch, mode * kunci[i % len(kunci)]))
            i += 1
        else:
            out.append(ch)
    return ''.join(out)

def bersihkan(teks):
    return re.sub('[^A-Z]', '', teks.upper())

def kasiski(cipher, panjang_ngram=3, maxlen=20):
    posisi = {}
    for i in range(len(cipher) - panjang_ngram + 1):
        posisi.setdefault(cipher[i:i + panjang_ngram], []).append(i)
    jarak = []
    for lst in posisi.values():
        for a, b in zip(lst, lst[1:]):
            jarak.append(b - a)
    skor = Counter()
    for d in jarak:
        for f in range(2, maxlen + 1):
            if d % f == 0:
                skor[f] += 1
    return (skor, jarak)

def ic(teks):
    n = len(teks)
    if n < 2:
        return 0.0
    c = Counter(teks)
    return sum((v * (v - 1) for v in c.values())) / (n * (n - 1))

def ic_rata2(cipher, panjang):
    kolom = [cipher[i::panjang] for i in range(panjang)]
    return sum((ic(k) for k in kolom)) / panjang

def tebak_panjang(cipher, maxlen=20, toleransi=0.88):
    tabel = {L: ic_rata2(cipher, L) for L in range(1, maxlen + 1)}
    terbaik = max(tabel, key=tabel.get)
    for d in range(1, terbaik + 1):
        if terbaik % d == 0 and tabel[d] >= toleransi * tabel[terbaik]:
            return (d, tabel)
    return (terbaik, tabel)

def chi_kuadrat(kolom, bahasa):
    n = len(kolom)
    cnt = Counter(kolom)
    total = sum(FREQ[bahasa])
    chi = 0.0
    for i, ch in enumerate(ALPHA):
        harap = n * FREQ[bahasa][i] / total
        chi += (cnt.get(ch, 0) - harap) ** 2 / harap
    return chi

def tebak_kunci(cipher, panjang, bahasa):
    kunci, detail = ('', [])
    for i in range(panjang):
        kolom = cipher[i::panjang]
        skor = []
        for s in range(26):
            dekripsi = ''.join((ALPHA[(ALPHA.index(c) - s) % 26] for c in kolom))
            skor.append((chi_kuadrat(dekripsi, bahasa), s))
        skor.sort()
        kunci += ALPHA[skor[0][1]]
        detail.append((i + 1, ALPHA[skor[0][1]], skor[0][0], ALPHA[skor[1][1]]))
    return (kunci, detail)

def pecahkan(ciphertext, bahasa='id', maxlen=20, verbose=True):
    bersih = bersihkan(ciphertext)
    if verbose:
        print(f'[1] Ciphertext bersih: {len(bersih)} huruf')
    skor, jarak = kasiski(bersih, 3, maxlen)
    if verbose:
        print(f'[2] Kasiski: {len(jarak)} jarak pengulangan trigram')
        if skor:
            print('    Faktor terbanyak:', skor.most_common(5))
        else:
            print('    Tidak ada pengulangan (teks terlalu pendek), andalkan IC.')
    L, tabel = tebak_panjang(bersih, maxlen)
    if verbose:
        print('[3] IC rata-rata per panjang kunci:')
        for k, v in tabel.items():
            tanda = '  <-- dipilih' if k == L else ''
            print(f'    L={k:2d}  IC={v:.4f}{tanda}')
    kunci, detail = tebak_kunci(bersih, L, bahasa)
    if verbose:
        print(f'[4] Chi-square per kolom (bahasa={bahasa}):')
        for kol, huruf, chi, runner in detail:
            print(f"    kolom {kol}: huruf kunci '{huruf}' (chi={chi:.1f}), runner-up '{runner}'")
        print(f'[5] Kunci terdeteksi: {kunci}')
    return (kunci, vigenere(ciphertext, kunci, -1))

def demo():
    pesan = 'Keamanan sistem tidak boleh bergantung pada kerahasiaan algoritma. Yang harus dijaga hanyalah kunci, sedangkan algoritma boleh diketahui siapa saja. Prinsip ini dikenal sebagai prinsip Kerckhoffs dan menjadi dasar kriptografi modern. Cipher Vigenere pernah dijuluki le chiffre indechiffrable, namun ternyata dapat dipecahkan dengan analisis frekuensi setelah panjang kuncinya diketahui.'
    kunci_asli = 'KRIPTO'
    cipher = vigenere(pesan, kunci_asli, +1)
    print('Kunci asli (rahasia):', kunci_asli)
    print('Ciphertext:', cipher, '\n')
    kunci, hasil = pecahkan(cipher, 'id')
    print('\nPlaintext hasil pecah:\n', hasil)
    print('\nBerhasil!' if kunci == kunci_asli else '\nKunci tidak cocok, coba teks lebih panjang.')
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Pemecah cipher Vigenere')
    ap.add_argument('-t', '--teks', help='ciphertext langsung')
    ap.add_argument('-f', '--file', help='file berisi ciphertext')
    ap.add_argument('--lang', choices=['id', 'en'], default='id')
    ap.add_argument('--maxlen', type=int, default=20)
    ap.add_argument('--demo', action='store_true')
    a = ap.parse_args()
    if a.demo or not (a.teks or a.file):
        demo()
    else:
        data = a.teks if a.teks else open(a.file, encoding='utf-8').read()
        k, p = pecahkan(data, a.lang, a.maxlen)
        print('\nPlaintext:\n', p)
