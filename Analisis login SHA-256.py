"""
Checkpoint 1 - Sang Pembongkar Sistem
Bagian 2: Analisis desain login  password -> SHA-256 -> database

Pemakaian:  python login_analysis.py
Hanya memakai pustaka standar Python (hashlib, hmac, os, time, base64).

Alur demo:
  0. Base64 vs SHA-256 (recap Praktikum 1A/1B)
  1. Desain naif: SHA-256 tanpa salt
  2. Serangan: DB bocor -> hash yang sama terlihat + wordlist + rainbow table
  3. Perbaikan setengah hati: SHA-256 + salt
  4. Akar masalah: kecepatan hash (SHA-256 vs KDF lambat)
  5. Desain lebih baik: salt unik + PBKDF2 + perbandingan konstan
  6. Kesimpulan properti keamanan
"""
import base64
import hashlib
import hmac
import os
import time

# Data pengguna "asli" (hanya diketahui sistem; attacker hanya melihat DB)
PENGGUNA = {
    "alice": "user123",
    "bob": "password",
    "charlie": "abc123!",
    "dave": "password",          # sama dengan bob
    "eve": "k7#Rm2!vQz9w",       # password acak yang kuat
}

WORDLIST = ["123456", "qwerty", "admin", "letmein", "welcome", "iloveyou",
            "password", "password1", "user123", "abc123", "abc123!", "12345678"]


def judul(teks):
    print("\n" + "=" * 64)
    print(" " + teks)
    print("=" * 64)


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ 0
def bagian0():
    judul("0. Base64 bukan enkripsi, SHA-256 bukan enkripsi")
    enc = base64.b64encode(b"user123").decode()
    print(f"Base64('user123')  = {enc}")
    print(f"Decode tanpa kunci = {base64.b64decode(enc).decode()}   -> bisa dibalik siapa saja")
    print(f"SHA-256('user123') = {sha256_hex('user123')[:32]}...")
    print(f"SHA-256('user124') = {sha256_hex('user124')[:32]}...   (1 karakter beda -> hash beda total)")
    print("Hash tidak punya fungsi 'decrypt', tetapi bisa DITEBAK dengan mencoba input satu per satu.")


# ------------------------------------------------------------------ 1
def bagian1():
    judul("1. Desain naif: password -> SHA-256 -> database (tanpa salt)")
    db = {}

    def register(user, pw):
        db[user] = sha256_hex(pw)

    def login(user, pw):
        return db.get(user) == sha256_hex(pw)

    for u, p in PENGGUNA.items():
        register(u, p)
    print("Isi database:")
    for u, h in db.items():
        print(f"  {u:8s} {h}")
    print(f"\nlogin(alice, user123) = {login('alice', 'user123')}")
    print(f"login(alice, salah)   = {login('alice', 'salah')}")
    print("Fungsional, tetapi apakah AMAN jika database bocor?")
    return db


# ------------------------------------------------------------------ 2
def bagian2(db):
    judul("2. Serangan setelah database bocor (attacker offline)")

    # a. pola hash yang sama
    print("a) Hash yang sama = password yang sama (kebocoran informasi):")
    kelompok = {}
    for u, h in db.items():
        kelompok.setdefault(h, []).append(u)
    for h, users in kelompok.items():
        if len(users) > 1:
            print(f"   {users} punya hash identik -> pasti password sama,")
            print("   cukup crack 1 hash untuk membuka semuanya.")

    # b. rainbow / lookup table (dibuat SEKALI, dipakai untuk semua korban)
    print("\nb) Lookup table (precomputed) - dibuat sekali, dipakai ke semua DB:")
    t0 = time.perf_counter()
    tabel = {sha256_hex(w): w for w in WORDLIST}
    print(f"   Tabel {len(tabel)} entri dibuat dalam {time.perf_counter() - t0:.4f} detik")
    retak = 0
    for u, h in db.items():
        if h in tabel:
            retak += 1
            print(f"   {u:8s} -> '{tabel[h]}'   (tanpa menghitung hash lagi)")
        else:
            print(f"   {u:8s} -> tidak ada di tabel")
    print(f"   Terbuka: {retak}/{len(db)} akun")
    print("\nCatatan: 'eve' selamat BUKAN karena SHA-256 kuat, tetapi karena")
    print("passwordnya tidak ada di wordlist. Keamanan bergantung pada kualitas password.")


# ------------------------------------------------------------------ 3
def bagian3():
    judul("3. Perbaikan 'kurang salt': SHA-256(salt + password)")
    db = {}
    for u, p in PENGGUNA.items():
        salt = os.urandom(8)
        db[u] = (salt, hashlib.sha256(salt + p.encode()).hexdigest())
    print("bob dan dave punya password sama, tetapi hash di DB:")
    print(f"  bob  : {db['bob'][1][:32]}...")
    print(f"  dave : {db['dave'][1][:32]}...  -> beda, pola hilang\n")

    print("Namun attacker masih bisa menyerang PER USER (salt ikut bocor di DB):")
    t0 = time.perf_counter()
    retak = 0
    percobaan = 0
    for u, (salt, h) in db.items():
        for w in WORDLIST:
            percobaan += 1
            if hashlib.sha256(salt + w.encode()).hexdigest() == h:
                retak += 1
                print(f"   {u:8s} -> '{w}'")
                break
    print(f"   Terbuka {retak}/{len(db)} akun dengan {percobaan} tebakan "
          f"dalam {time.perf_counter() - t0:.4f} detik")
    print("\nSalt mematikan lookup table & pola hash sama, tetapi TIDAK memperlambat tebakan.")
    print("Jadi 'kurang salt' hanya sebagian kecil dari masalah.")


# ------------------------------------------------------------------ 4
def bagian4():
    judul("4. Akar masalah: SHA-256 dirancang CEPAT")
    n = 300000
    t0 = time.perf_counter()
    for i in range(n):
        hashlib.sha256(str(i).encode()).digest()
    cepat = n / (time.perf_counter() - t0)

    m = 10
    salt = b"salt-unik"
    t0 = time.perf_counter()
    for i in range(m):
        hashlib.pbkdf2_hmac("sha256", str(i).encode(), salt, 200000)
    lambat = m / (time.perf_counter() - t0)

    scrypt_rate = None
    try:
        k = 5
        t0 = time.perf_counter()
        for i in range(k):
            hashlib.scrypt(str(i).encode(), salt=salt, n=2 ** 14, r=8, p=1)
        scrypt_rate = k / (time.perf_counter() - t0)
    except (AttributeError, ValueError):
        pass

    print(f"SHA-256 polos   : {cepat:>14,.0f} tebakan/detik (1 core CPU)")
    print(f"PBKDF2 (200k)   : {lambat:>14,.1f} tebakan/detik")
    if scrypt_rate:
        print(f"scrypt (n=2^14) : {scrypt_rate:>14,.1f} tebakan/detik")
    print(f"Rasio SHA-256 vs PBKDF2: ~{cepat / lambat:,.0f}x")

    print("\nEstimasi waktu menghabiskan ruang password (hanya aritmetika dari benchmark di atas):")
    gpu = 1e10  # ASUMSI: ~10 miliar SHA-256/detik pada satu GPU modern. Ganti dgn data hashcat.
    kasus = [("6 huruf kecil", 26 ** 6), ("8 huruf kecil", 26 ** 8),
             ("8 karakter campuran (95)", 95 ** 8)]
    print(f"  {'ruang password':28s}{'SHA-256 (CPU)':>22s}{'SHA-256 (GPU*)':>22s}{'PBKDF2 (CPU)':>22s}")
    for nama, ruang in kasus:
        print(f"  {nama:28s}{fmt_waktu(ruang / cepat):>22s}{fmt_waktu(ruang / gpu):>22s}"
              f"{fmt_waktu(ruang / lambat):>22s}")
    print("  *GPU memakai asumsi 1e10 hash/detik, bukan hasil pengukuran di sini.")


def fmt_waktu(detik):
    if detik < 1:
        return "< 1 detik"
    for batas, nama in [(31536000, "tahun"), (86400, "hari"), (3600, "jam"), (60, "menit")]:
        if detik >= batas:
            return f"{detik / batas:,.1f} {nama}"
    return f"{detik:,.0f} detik"


# ------------------------------------------------------------------ 5
ITERASI = 200000


def daftar(db, user, pw):
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, ITERASI)
    db[user] = (salt, ITERASI, h)


def masuk(db, user, pw):
    if user not in db:
        # lakukan kerja palsu agar waktu respons tidak membocorkan keberadaan user
        hashlib.pbkdf2_hmac("sha256", pw.encode(), b"0" * 16, ITERASI)
        return False
    salt, iters, h = db[user]
    kandidat = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return hmac.compare_digest(kandidat, h)


def bagian5():
    judul("5. Desain yang lebih baik: salt unik + KDF lambat + compare konstan")
    db = {}
    for u, p in PENGGUNA.items():
        daftar(db, u, p)
    print(f"bob  : salt={db['bob'][0].hex()[:16]}... hash={db['bob'][2].hex()[:24]}...")
    print(f"dave : salt={db['dave'][0].hex()[:16]}... hash={db['dave'][2].hex()[:24]}...")
    print(f"masuk(alice, user123)   = {masuk(db, 'alice', 'user123')}")
    print(f"masuk(alice, salah)     = {masuk(db, 'alice', 'salah')}")
    print(f"masuk(tidak_ada, apa)   = {masuk(db, 'tidak_ada', 'apa')}")
    print("\nPerbaikan ini MEMPERLAMBAT attacker, tetapi tidak membuat password lemah jadi kuat.")
    print("Pelengkap yang tidak didemokan di sini: rate limiting/lockout, TLS, MFA,")
    print("pepper yang disimpan terpisah dari DB, dan kebijakan password.")


# ------------------------------------------------------------------ 6
def bagian6():
    judul("6. Kesimpulan")
    print("""Apakah desain  password -> SHA-256 -> database  aman? TIDAK.

Properti keamanan yang gagal:
  - Confidentiality password saat DB bocor: hash dapat ditebak offline dengan cepat.
  - Kebocoran informasi: hash identik membuka siapa yang berbagi password.
  - Tidak ada perlindungan terhadap serangan online (rate limit/lockout).

Alasan bukan sekadar 'kurang salt':
  - Salt hanya mematikan lookup table dan pola hash sama.
  - Masalah inti adalah fungsi hash yang CEPAT dipakai untuk menyimpan password
    yang entropinya RENDAH, sehingga ruang tebakan manusia mudah dihabiskan.
  - Preimage resistance SHA-256 melindungi dari 'membalik hash', bukan dari 'menebak input'.

Perbaikan: KDF lambat (Argon2id/bcrypt/scrypt/PBKDF2 dgn iterasi tinggi) + salt unik per user
+ rate limiting + TLS + MFA.""")


def main():
    bagian0()
    db = bagian1()
    bagian2(db)
    bagian3()
    bagian4()
    bagian5()
    bagian6()


if __name__ == "__main__":
    main()
