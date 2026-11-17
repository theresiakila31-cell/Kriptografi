"""
Checkpoint 1 - Sang Pembongkar Sistem
Bagian 1: Pemecah Vigenere (Kasiski + Index of Coincidence + chi-square)

Pemakaian:
  python vigenere_breaker.py                      -> demo (ciphertext dibuat sendiri)
  python vigenere_breaker.py ciphertext.txt       -> pecahkan ciphertext dari file
  python vigenere_breaker.py ciphertext.txt --lang en
  (tambahkan --lang en bila plaintext berbahasa Inggris, default: id)

Alur deduksi yang dicetak:
  1. Hitung IC teks utuh (apakah polialfabetik?)
  2. Kasiski: cari pola berulang -> jarak -> faktor
  3. Tabel rata-rata IC per panjang kunci -> pilih panjang kunci
  4. Pecah tiap kolom sebagai Caesar (chi-square vs frekuensi bahasa)
  5. Susun kunci, dekripsi, verifikasi
"""
import sys
import string
from collections import Counter

ALFABET = string.ascii_uppercase

# Frekuensi huruf (persen, perkiraan). Akan dinormalisasi di fungsi frekuensi().
FREQ_ID = [20.4, 3.0, 0.9, 3.4, 7.3, 0.2, 3.4, 2.1, 7.9, 1.0, 4.8, 4.2, 3.9,
           9.9, 2.2, 2.7, 0.0, 5.2, 4.2, 4.8, 4.8, 0.1, 0.7, 0.0, 0.8, 0.1]
FREQ_EN = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77,
           4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98,
           2.36, 0.15, 1.97, 0.07]
IC_ACAK = 1.0 / 26  # ~0.0385


def frekuensi(lang):
    f = FREQ_ID if lang == "id" else FREQ_EN
    total = sum(f)
    return [x / total for x in f]


def bersihkan(teks):
    return "".join(c for c in teks.upper() if c in ALFABET)


# ---------------------------------------------------------------- cipher
def vigenere_encrypt(plaintext, key):
    plaintext = bersihkan(plaintext)
    key = bersihkan(key)
    hasil = []
    for i, ch in enumerate(plaintext):
        p = ord(ch) - 65
        k = ord(key[i % len(key)]) - 65
        hasil.append(chr((p + k) % 26 + 65))
    return "".join(hasil)


def vigenere_decrypt(ciphertext, key):
    ciphertext = bersihkan(ciphertext)
    key = bersihkan(key)
    hasil = []
    for i, ch in enumerate(ciphertext):
        c = ord(ch) - 65
        k = ord(key[i % len(key)]) - 65
        hasil.append(chr((c - k) % 26 + 65))
    return "".join(hasil)


# ---------------------------------------------------------------- analisis
def index_of_coincidence(teks):
    n = len(teks)
    if n < 2:
        return 0.0
    cnt = Counter(teks)
    return sum(f * (f - 1) for f in cnt.values()) / (n * (n - 1))


def kasiski(ct, seq_len=3, maks_kunci=20):
    """Cari pola berulang, hitung jarak, hitung faktor pembagi."""
    posisi = {}
    for i in range(len(ct) - seq_len + 1):
        posisi.setdefault(ct[i:i + seq_len], []).append(i)

    jarak = []
    contoh = []
    for seq, pos in posisi.items():
        if len(pos) > 1:
            g = [pos[j] - pos[j - 1] for j in range(1, len(pos))]
            jarak.extend(g)
            contoh.append((seq, pos, g))

    print(f"  Pola {seq_len}-huruf yang berulang: {len(contoh)}")
    for seq, pos, g in contoh[:6]:
        print(f"   - '{seq}' di indeks {pos[:5]} -> jarak {g[:5]}")
    if len(contoh) > 6:
        print(f"   ... dan {len(contoh) - 6} pola lain")

    faktor = Counter()
    for g in jarak:
        for f in range(2, maks_kunci + 1):
            if g % f == 0:
                faktor[f] += 1

    if not faktor:
        print("  [!] Tidak ada repetisi. Teks terlalu pendek untuk Kasiski.")
        return None, faktor

    print("  Faktor paling sering (kandidat panjang kunci):")
    for f, n in faktor.most_common(5):
        print(f"   - panjang {f:2d}: muncul {n}x")
    return faktor.most_common(1)[0][0], faktor


def tabel_ic(ct, maks=20):
    """Rata-rata IC kolom untuk tiap kemungkinan panjang kunci."""
    hasil = {}
    for k in range(1, min(maks, len(ct) // 3) + 1):
        kolom = [ct[i::k] for i in range(k)]
        hasil[k] = sum(index_of_coincidence(c) for c in kolom) / k
    return hasil


def pilih_panjang(tabel):
    """Panjang kunci terkecil yang IC-nya mendekati maksimum
    (kelipatan panjang kunci sebenarnya juga punya IC tinggi)."""
    terbesar = max(tabel.values())
    for k in sorted(tabel):
        if tabel[k] >= 0.9 * terbesar:
            return k


def chi_square(kolom, shift, freq):
    n = len(kolom)
    cnt = Counter(kolom)
    skor = 0.0
    for i in range(26):
        # huruf cipher (i+shift) berasal dari plaintext huruf i
        teramati = cnt.get(ALFABET[(i + shift) % 26], 0)
        diharapkan = max(freq[i], 0.0005) * n
        skor += (teramati - diharapkan) ** 2 / diharapkan
    return skor


def pecah_kolom(kolom, freq):
    skor = sorted((chi_square(kolom, s, freq), s) for s in range(26))
    return skor


# ---------------------------------------------------------------- utama
def pecahkan(ct, lang="id", kunci_asli=None):
    ct = bersihkan(ct)
    freq = frekuensi(lang)
    ic_bahasa = sum(p * p for p in freq)

    print("=" * 62)
    print(" PEMECAH VIGENERE - langkah deduksi")
    print("=" * 62)
    print(f"Panjang ciphertext: {len(ct)} huruf")

    # Langkah 1
    print("\n[Langkah 1] Index of Coincidence teks utuh")
    ic_all = index_of_coincidence(ct)
    print(f"  IC ciphertext      : {ic_all:.4f}")
    print(f"  IC bahasa ({lang})    : {ic_bahasa:.4f}  (monoalfabetik mendekati ini)")
    print(f"  IC acak (1/26)     : {IC_ACAK:.4f}  (polialfabetik mendekati ini)")
    if ic_all < (ic_bahasa + IC_ACAK) / 2:
        print("  -> IC rendah: kemungkinan besar cipher POLIALFABETIK (mis. Vigenere).")
    else:
        print("  -> IC tinggi: kemungkinan monoalfabetik (Caesar/substitusi).")

    # Langkah 2
    print("\n[Langkah 2] Kasiski examination")
    tebak_kasiski, _ = kasiski(ct)

    # Langkah 3
    print("\n[Langkah 3] Rata-rata IC kolom per panjang kunci")
    tabel = tabel_ic(ct)
    terbesar = max(tabel.values())
    for k, v in tabel.items():
        bar = "#" * int(v / terbesar * 30)
        print(f"  k={k:2d}  IC={v:.4f}  {bar}")
    k = pilih_panjang(tabel)
    print(f"  -> Panjang kunci terpilih (IC): {k}")
    if tebak_kasiski:
        status = "KONSISTEN" if tebak_kasiski % k == 0 or k % tebak_kasiski == 0 else "BEDA"
        print(f"  -> Kasiski menyarankan {tebak_kasiski}: {status} dengan hasil IC")

    # Langkah 4
    print(f"\n[Langkah 4] Pecah {k} kolom sebagai Caesar (chi-square, makin kecil makin cocok)")
    kunci = ""
    for i in range(k):
        kolom = ct[i::k]
        top = Counter(kolom).most_common(3)
        skor = pecah_kolom(kolom, freq)
        s = skor[0][1]
        kunci += ALFABET[s]
        top_str = ", ".join(f"{h}:{n}" for h, n in top)
        kandidat = ", ".join(f"{ALFABET[sh]}(chi={sc:.0f})" for sc, sh in skor[:3])
        print(f"  Kolom {i + 1}: {len(kolom)} huruf | tersering {top_str}")
        print(f"           kandidat huruf kunci: {kandidat}")

    # Langkah 5
    print("\n[Langkah 5] Hasil")
    plaintext = vigenere_decrypt(ct, kunci)
    print(f"  Kunci ditemukan : {kunci}")
    print(f"  Plaintext       : {plaintext[:120]}{'...' if len(plaintext) > 120 else ''}")
    if kunci_asli:
        cocok = bersihkan(kunci_asli) == kunci
        print(f"  Kunci asli      : {kunci_asli}  -> {'COCOK' if cocok else 'TIDAK COCOK'}")
    return kunci, plaintext


DEMO_PLAINTEXT = (
    "KRIPTOGRAFI KLASIK TIDAK AMAN KARENA POLA BAHASA TETAP TERLIHAT DALAM "
    "CIPHERTEXT MESKIPUN HURUF YANG SAMA BISA BERUBAH MENJADI HURUF LAIN "
    "SEORANG ANALIS CUKUP MENGHITUNG FREKUENSI HURUF PADA SETIAP KOLOM UNTUK "
    "MENEMUKAN KUNCI RAHASIA YANG DIPAKAI OLEH PENGIRIM PESAN SEHINGGA "
    "KERAHASIAAN SAJA TIDAK CUKUP UNTUK MENJAMIN KEAMANAN SEBUAH SISTEM "
    "KITA HARUS MEMAHAMI MODEL PENYERANG SEBELUM MEMILIH ALGORITMA YANG AKAN "
    "DIGUNAKAN DAN SEBUAH ALGORITMA YANG HANYA BERGANTUNG PADA KERUMITAN "
    "BUKAN PADA KUNCI YANG SULIT DITEBAK AKAN SELALU GAGAL MENGHADAPI "
    "PENYERANG YANG SABAR DAN TELITI DALAM MENGAMATI POLA PADA CIPHERTEXT"
)


def main():
    lang = "id"
    if "--lang" in sys.argv:
        lang = sys.argv[sys.argv.index("--lang") + 1]
    args = [a for a in sys.argv[1:] if not a.startswith("--") and a not in ("id", "en")]

    if args:
        with open(args[0], "r", encoding="utf-8") as f:
            ct = f.read()
        pecahkan(ct, lang)
    else:
        kunci_asli = "SANDI"
        ct = vigenere_encrypt(DEMO_PLAINTEXT, kunci_asli)
        print("MODE DEMO: ciphertext dibuat dari plaintext bahasa Indonesia")
        print(f"Kunci rahasia (disembunyikan dari pemecah): {kunci_asli}")
        print(f"Ciphertext: {ct[:60]}...\n")
        pecahkan(ct, lang, kunci_asli)


if __name__ == "__main__":
    main()
