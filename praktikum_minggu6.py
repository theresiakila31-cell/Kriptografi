"""
Praktikum Kriptografi Minggu 6: Hash, HMAC, dan Password Hashing
Semua praktik dalam satu file.

  Praktik 1: Sifat Dasar Hash dan Avalanche Effect
  Praktik 2: Kegagalan Collision Resistance pada MD5
  Praktik 3: Verifikasi Integritas File, Batas Hash Biasa, dan HMAC
  Praktik 4: Password Hashing (SHA-256, Salt, bcrypt, Argon2id)

Cara pakai:
  python praktikum6_hash.py        -> jalankan semua praktik
  python praktikum6_hash.py 2      -> jalankan Praktik 2 saja
  python praktikum6_hash.py 1 3    -> jalankan Praktik 1 dan 3

Instalasi (khusus Praktik 4): pip install bcrypt argon2-cffi
"""

import hashlib
import hmac
import os
import random
import secrets
import statistics
import sys
import tempfile
import time


def garis(judul: str) -> None:
    print()
    print("=" * 64)
    print(judul)
    print("=" * 64)


def praktik1():
    """Praktik 1: Sifat Dasar Hash dan Avalanche Effect"""
    SEED = 2026          # seed tetap agar hasil semua mahasiswa sama
    JUMLAH_UJI = 1000    # jumlah percobaan avalanche

    def bit_beda(a: bytes, b: bytes) -> int:
        """Hitung jumlah bit yang berbeda antara dua digest berpanjang sama."""
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    def balik_satu_bit(data: bytes, posisi_bit: int) -> bytes:
        """Kembalikan salinan data dengan tepat satu bit dibalik."""
        hasil = bytearray(data)
        hasil[posisi_bit // 8] ^= 1 << (posisi_bit % 8)
        return bytes(hasil)

    def hash_lemah(data: bytes) -> bytes:
        """
        Fungsi 'hash' buatan yang TIDAK aman, hanya sebagai pembanding:
        jumlah seluruh byte, modulo 2^32, output 4 byte (32 bit).
        """
        return (sum(data) % 2**32).to_bytes(4, "big")

    # ------------------------------------------------------------------
    # BAGIAN 1: Deterministik dan panjang output tetap (slide 6)
    # ------------------------------------------------------------------
    garis("BAGIAN 1. Deterministik dan panjang output tetap")

    teks = b"Keamanan Data"
    print(f"\nInput: {teks.decode()!r}, dihitung tiga kali dengan SHA-256:")
    for i in range(1, 4):
        print(f"  Run {i}: {hashlib.sha256(teks).hexdigest()}")

    data_besar = random.Random(SEED).randbytes(5 * 1024 * 1024)  # 5 MB
    print(f"\nInput kecil : {len(teks):>9,} byte -> SHA-256 "
          f"{len(hashlib.sha256(teks).hexdigest())} karakter heksadesimal")
    print(f"Input besar : {len(data_besar):>9,} byte -> SHA-256 "
          f"{len(hashlib.sha256(data_besar).hexdigest())} karakter heksadesimal")

    print("\nPanjang digest berbagai algoritma untuk input yang sama:")
    print(f"  {'Algoritma':<12} {'Bit':>5}  Digest (16 karakter pertama)")
    for nama in ["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"]:
        h = hashlib.new(nama, teks)
        print(f"  {nama:<12} {h.digest_size * 8:>5}  {h.hexdigest()[:16]}...")

    print("\nSHAKE256 adalah XOF: panjang output dipilih oleh pemakai (slide 14).")
    for panjang_byte in (16, 32, 64):
        out = hashlib.shake_256(teks).hexdigest(panjang_byte)
        print(f"  SHAKE256, {panjang_byte * 8:>4} bit: {out}")

    # ------------------------------------------------------------------
    # BAGIAN 2: Avalanche effect, satu contoh (slide 7)
    # ------------------------------------------------------------------
    garis("BAGIAN 2. Avalanche effect, satu contoh")

    pasangan = [(b"hello", b"hfllo"), (b"Data penting", b"Data pentIng")]
    for asli, ubah in pasangan:
        h1 = hashlib.sha256(asli).digest()
        h2 = hashlib.sha256(ubah).digest()
        beda = bit_beda(h1, h2)
        print(f"\n  {asli.decode()!r:<16} -> {h1.hex()}")
        print(f"  {ubah.decode()!r:<16} -> {h2.hex()}")
        print(f"  Bit berbeda: {beda} dari 256 ({beda / 256 * 100:.1f}%)")

    print("\nCatatan: satu contoh belum membuktikan apa pun secara statistik.")
    print("Bagian 3 mengulang percobaan ini sebanyak", JUMLAH_UJI, "kali.")

    # ------------------------------------------------------------------
    # BAGIAN 3: Avalanche effect secara statistik
    # ------------------------------------------------------------------
    garis(f"BAGIAN 3. Avalanche effect secara statistik ({JUMLAH_UJI} percobaan)")
    print("\nSetiap percobaan: pesan acak 32 byte, balik TEPAT 1 bit,")
    print("lalu hitung berapa persen bit digest yang ikut berubah.")

    rng = random.Random(SEED)
    fungsi = {
        "SHA-256": lambda d: hashlib.sha256(d).digest(),
        "SHA3-256": lambda d: hashlib.sha3_256(d).digest(),
        "hash_lemah": hash_lemah,
    }
    hasil = {nama: [] for nama in fungsi}

    for _ in range(JUMLAH_UJI):
        pesan = rng.randbytes(32)
        pesan_ubah = balik_satu_bit(pesan, rng.randrange(256))
        for nama, f in fungsi.items():
            d1, d2 = f(pesan), f(pesan_ubah)
            hasil[nama].append(bit_beda(d1, d2) / (len(d1) * 8) * 100)

    print(f"\n  {'Fungsi':<11} {'Rata-rata':>10} {'Std dev':>9} {'Min':>7} {'Maks':>7}")
    for nama, nilai in hasil.items():
        print(f"  {nama:<11} {statistics.mean(nilai):>9.1f}% "
              f"{statistics.stdev(nilai):>8.1f}% {min(nilai):>6.1f}% {max(nilai):>6.1f}%")

    batas = [(0, 10), (10, 20), (20, 30), (30, 40), (40, 45), (45, 50),
             (50, 55), (55, 60), (60, 101)]
    for nama in ("SHA-256", "hash_lemah"):
        print(f"\nSebaran persentase bit berubah, {nama} (panjang bar relatif):")
        hitung = [sum(b <= v < a for v in hasil[nama]) for b, a in batas]
        skala = max(hitung) / 40
        for (bawah, atas), n in zip(batas, hitung):
            label = f"{bawah}-{min(atas, 100)}%"
            print(f"  {label:>8} | {'#' * round(n / skala):<40} {n}")

    print("\nOBSERVASI:")
    print("  -> SHA-256 dan SHA3-256 berpusat di sekitar 50% dengan sebaran sempit.")
    print("  -> hash_lemah hanya mengubah sedikit bit: hubungan input dan output")
    print("     mudah ditebak, sehingga tidak layak dipakai untuk keamanan.")
    print("  -> Avalanche effect adalah karakteristik desain yang penting, tetapi")
    print("     tidak sama dengan preimage atau collision resistance (slide 7-8).")


def praktik2():
    """Praktik 2: Kegagalan Collision Resistance pada MD5"""
    BLOK_A = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c"
        "2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a"
        "085125e8f7cdc99fd91dbdf280373c5b"
        "960b1dd1dc417b9ce4d897f45a6555d5"
        "35739ac7f0ebfd0c3029f166d109b18f"
        "75277f7930d55ceb22e8adba79cc155c"
        "ed74cbdd5fc5d36db19b0ad835cca7e3"
    )

    BLOK_B = bytes.fromhex(
        "d131dd02c5e6eec4693d9a0698aff95c"
        "2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e4888325f1415a"
        "085125e8f7cdc99fd91dbd7280373c5b"
        "960b1dd1dc417b9ce4d897f45a6555d5"
        "35739a47f0ebfd0c3029f166d109b18f"
        "75277f7930d55ceb22e8adba794c155c"
        "ed74cbdd5fc5d36db19b0a5835cca7e3"
    )

    assert len(BLOK_A) == len(BLOK_B) == 128  # dua blok MD5 @ 64 byte

    def md5(data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    # ------------------------------------------------------------------
    # BAGIAN 1: Collision MD5
    # ------------------------------------------------------------------
    garis("BAGIAN 1. Dua data berbeda, MD5 identik")

    posisi_beda = [i for i, (a, b) in enumerate(zip(BLOK_A, BLOK_B)) if a != b]
    print(f"\nPanjang masing-masing blok : {len(BLOK_A)} byte")
    print(f"Jumlah byte yang berbeda   : {len(posisi_beda)}")
    print("Posisi byte yang berbeda   :", posisi_beda)
    for p in posisi_beda:
        print(f"  byte ke-{p:<3}: A = 0x{BLOK_A[p]:02x}   B = 0x{BLOK_B[p]:02x}")

    print(f"\nMD5(A) = {md5(BLOK_A)}")
    print(f"MD5(B) = {md5(BLOK_B)}")
    print(f"\nData sama : {BLOK_A == BLOK_B}")
    print(f"MD5 sama  : {md5(BLOK_A) == md5(BLOK_B)}")

    print("\nOBSERVASI:")
    print("  -> Ini collision identical-prefix: kedua pesan berawal dari kondisi")
    print("     yang sama (di sini: IV standar MD5), lalu blok collision dihitung")
    print("     secara sengaja. Bukan kebetulan dan bukan hasil brute force.")

    # ------------------------------------------------------------------
    # BAGIAN 2: Satu collision, banyak file
    # ------------------------------------------------------------------
    garis("BAGIAN 2. Satu collision dapat diperpanjang")

    print("\nMD5 memproses data per blok 64 byte (konstruksi Merkle-Damgard).")
    print("Setelah A dan B diproses, state internal MD5 sudah IDENTIK.")
    print("Akibatnya, menambahkan sufiks yang sama tetap menghasilkan collision.\n")

    sufiks_list = [
        b"",
        b" Transfer ke rekening 1234567890 sebesar Rp 1.000.000",
        b" " + b"X" * 1000,
    ]
    for s in sufiks_list:
        ma, mb = md5(BLOK_A + s), md5(BLOK_B + s)
        print(f"  sufiks {len(s):>4} byte -> MD5 sama: {ma == mb}  ({ma})")

    print("\nSebaliknya, jika PREFIKS diubah, state awal berbeda dan collision hilang:\n")
    for p in [b"", b"Z", b"Header dokumen v2\n"]:
        ma, mb = md5(p + BLOK_A), md5(p + BLOK_B)
        print(f"  prefiks {len(p):>3} byte -> MD5 sama: {ma == mb}")

    print("\nOBSERVASI:")
    print("  -> Penyerang cukup menemukan satu collision, lalu dapat menempelkan")
    print("     isi apa pun di belakangnya. Inilah dasar pembuatan dua program atau")
    print("     dua dokumen berbeda dengan MD5 yang sama.")
    print("  -> Collision identical-prefix mensyaratkan prefiks yang sama.")
    print("     Varian yang lebih kuat, chosen-prefix collision (Stevens, Lenstra,")
    print("     de Weger, 2007), mengizinkan dua prefiks BERBEDA pilihan penyerang.")

    # ------------------------------------------------------------------
    # BAGIAN 3: Algoritma lain pada data yang sama
    # ------------------------------------------------------------------
    garis("BAGIAN 3. Data yang sama pada SHA-1, SHA-256, SHA3-256")

    for nama in ["md5", "sha1", "sha256", "sha3_256"]:
        ha = hashlib.new(nama, BLOK_A).hexdigest()
        hb = hashlib.new(nama, BLOK_B).hexdigest()
        print(f"\n  {nama:<9} A: {ha}")
        print(f"  {'':<9} B: {hb}")
        print(f"  {'':<9} sama: {ha == hb}")

    print("\nOBSERVASI:")
    print("  -> Blok collision ini dirancang khusus untuk struktur internal MD5,")
    print("     sehingga tidak berlaku pada algoritma lain.")
    print("  -> Hasil ini TIDAK membuktikan SHA-256 bebas collision. Hasil ini")
    print("     hanya menunjukkan bahwa serangan tersebut spesifik terhadap MD5.")

    # ------------------------------------------------------------------
    # BAGIAN 4: Kasus nyata
    # ------------------------------------------------------------------
    garis("BAGIAN 4. Kasus nyata kegagalan collision resistance")

    kasus = [
        ("2008", "Rogue CA certificate (MD5, chosen-prefix)",
         "Sotirov, Stevens, dkk. memperoleh sertifikat dari CA komersial yang\n"
         "        masih memakai MD5, lalu membuat sertifikat CA palsu dengan\n"
         "        tanda tangan yang tetap valid. CA palsu dapat menerbitkan\n"
         "        sertifikat untuk domain apa pun."),
        ("2012", "Malware Flame (MD5, chosen-prefix)",
         "Penyerang memalsukan sertifikat code-signing yang berantai ke root\n"
         "        Microsoft, lalu menyebarkan malware bertanda tangan 'sah' melalui\n"
         "        mekanisme Windows Update palsu di jaringan lokal."),
        ("2017", "SHAttered (SHA-1, identical-prefix)",
         "Google dan CWI menghasilkan dua file PDF berbeda dengan SHA-1 identik.\n"
         "        Collision praktis pertama untuk SHA-1."),
        ("2020", "SHA-1 is a Shambles (SHA-1, chosen-prefix)",
         "Leurent dan Peyrin mendemonstrasikan chosen-prefix collision SHA-1\n"
         "        dan memakainya untuk memalsukan identitas pada PGP Web of Trust."),
    ]
    for tahun, judul, isi in kasus:
        print(f"\n  [{tahun}] {judul}")
        print(f"        {isi}")

    print("\nCatatan tentang Git:")
    print("  Git masih memakai SHA-1 secara default, tetapi sejak versi 2.13 (2017)")
    print("  memakai SHA-1DC yang mendeteksi pola serangan collision yang dikenal.")
    print("  Format objek SHA-256 sudah tersedia dan direncanakan menjadi default")
    print("  di Git 3.0. Belum ada serangan collision nyata terhadap repository Git.")

    print("\nKESIMPULAN:")
    print("  MD5 dan SHA-1 tidak layak untuk keperluan yang membutuhkan collision")
    print("  resistance: sertifikat, tanda tangan digital, dan verifikasi software.")
    print("  Untuk aplikasi baru gunakan SHA-2 atau SHA-3 (slide 10-11).")


def praktik3():
    """Praktik 3: Verifikasi Integritas File, Batas Hash Biasa, dan HMAC"""
    def sha256_file(path: str, ukuran_chunk: int = 64 * 1024) -> str:
        """Hitung SHA-256 file per potongan, seperti Get-FileHash / sha256sum."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while potongan := f.read(ukuran_chunk):
                h.update(potongan)
        return h.hexdigest()

    def hmac_file(key: bytes, path: str, ukuran_chunk: int = 64 * 1024) -> str:
        """Hitung HMAC-SHA-256 file per potongan."""
        m = hmac.new(key, digestmod=hashlib.sha256)
        with open(path, "rb") as f:
            while potongan := f.read(ukuran_chunk):
                m.update(potongan)
        return m.hexdigest()

    def status(cocok: bool) -> str:
        return "LOLOS (dianggap asli)" if cocok else "GAGAL (perubahan terdeteksi)"

    folder = tempfile.mkdtemp(prefix="praktik3_")
    file_rilis = os.path.join(folder, "aplikasi_v1.2.bin")

    # Simulasi file rilis 3 MB
    with open(file_rilis, "wb") as f:
        f.write(b"MZ" + bytes(range(256)) * 12_000)

    # ------------------------------------------------------------------
    # BAGIAN 1: Publisher mempublikasikan digest (slide 16)
    # ------------------------------------------------------------------
    garis("BAGIAN 1. Publisher mempublikasikan SHA-256")

    digest_resmi = sha256_file(file_rilis)
    print(f"\nFile          : {os.path.basename(file_rilis)} "
          f"({os.path.getsize(file_rilis):,} byte)")
    print(f"SHA-256 resmi : {digest_resmi}")
    print("\nPerintah setara di sistem operasi:")
    print("  Windows : Get-FileHash aplikasi_v1.2.bin -Algorithm SHA256")
    print("  Linux   : sha256sum aplikasi_v1.2.bin")

    # ------------------------------------------------------------------
    # BAGIAN 2: Skenario A, file rusak atau diubah saat distribusi
    # ------------------------------------------------------------------
    garis("BAGIAN 2. Skenario A: file diubah, digest resmi tidak tersentuh")

    with open(file_rilis, "r+b") as f:
        f.seek(1_000_000)
        f.write(b"\x90")  # satu byte diubah di tengah file

    digest_unduhan = sha256_file(file_rilis)
    print(f"\nSHA-256 resmi   : {digest_resmi}")
    print(f"SHA-256 unduhan : {digest_unduhan}")
    print(f"Hasil verifikasi: {status(digest_unduhan == digest_resmi)}")

    # ------------------------------------------------------------------
    # BAGIAN 3: Skenario B, penyerang menguasai server
    # ------------------------------------------------------------------
    garis("BAGIAN 3. Skenario B: penyerang mengganti file DAN digest")

    with open(file_rilis, "ab") as f:
        f.write(b"<payload berbahaya>")

    digest_palsu = sha256_file(file_rilis)  # siapa pun dapat menghitung SHA-256
    print("\nPenyerang menyisipkan payload, lalu menghitung SHA-256 baru dan")
    print("mengganti digest yang tertera di halaman unduhan.")
    print(f"\nSHA-256 di halaman (palsu): {digest_palsu}")
    print(f"SHA-256 file unduhan      : {sha256_file(file_rilis)}")
    print(f"Hasil verifikasi          : {status(sha256_file(file_rilis) == digest_palsu)}")
    print("\nOBSERVASI:")
    print("  -> Hash biasa tidak memakai kunci. Siapa pun yang dapat mengubah file")
    print("     juga dapat menghitung digest baru. Hash membuktikan integritas")
    print("     HANYA jika digest diperoleh dari saluran yang tepercaya.")

    # ------------------------------------------------------------------
    # BAGIAN 4: HMAC (slide 15)
    # ------------------------------------------------------------------
    garis("BAGIAN 4. HMAC-SHA-256: hash + secret key")

    # Kembalikan file ke kondisi asli
    with open(file_rilis, "wb") as f:
        f.write(b"MZ" + bytes(range(256)) * 12_000)

    kunci = secrets.token_bytes(32)  # dibagi antara pengirim dan penerima saja
    tag_resmi = hmac_file(kunci, file_rilis)
    print(f"\nKunci rahasia (contoh) : {kunci.hex()[:16]}... (32 byte)")
    print(f"Tag HMAC resmi         : {tag_resmi}")

    # Penyerang mengubah file dan mencoba membuat tag dengan kunci tebakan
    with open(file_rilis, "ab") as f:
        f.write(b"<payload berbahaya>")
    kunci_tebakan = secrets.token_bytes(32)
    tag_penyerang = hmac_file(kunci_tebakan, file_rilis)

    tag_dihitung_penerima = hmac_file(kunci, file_rilis)
    print("\nPenyerang mengubah file dan membuat tag dengan kunci tebakan.")
    print(f"Tag dari penyerang     : {tag_penyerang}")
    print(f"Tag dihitung penerima  : {tag_dihitung_penerima}")
    cocok = hmac.compare_digest(tag_dihitung_penerima, tag_penyerang)
    print(f"Hasil verifikasi       : {status(cocok)}")

    print("\nOBSERVASI:")
    print("  -> Tanpa kunci, penyerang tidak dapat membuat tag yang valid.")
    print("  -> Perbandingan memakai hmac.compare_digest (waktu konstan), bukan '=='")
    print("     agar waktu perbandingan tidak membocorkan informasi tentang tag.")
    print("  -> HMAC menuntut kunci yang SAMA di kedua pihak. Untuk distribusi")
    print("     software ke publik, pengguna tidak boleh memegang kunci rahasia")
    print("     publisher, sehingga solusinya adalah digital signature (slide 17).")

    # Bersihkan
    os.remove(file_rilis)
    os.rmdir(folder)

    print("\nRINGKASAN:")
    print(f"  {'Mekanisme':<20} {'Integritas':<12} {'Autentikasi':<13} {'Kunci'}")
    print(f"  {'-' * 20} {'-' * 12} {'-' * 13} {'-' * 22}")
    print(f"  {'SHA-256':<20} {'ya*':<12} {'tidak':<13} {'tidak ada'}")
    print(f"  {'HMAC-SHA-256':<20} {'ya':<12} {'ya':<13} {'rahasia bersama'}")
    print(f"  {'Digital signature':<20} {'ya':<12} {'ya':<13} {'privat / publik'}")
    print("  * hanya jika digest diperoleh dari saluran tepercaya")


def praktik4():
    """Praktik 4: Password Hashing (SHA-256, Salt, bcrypt, Argon2id)"""
    try:
        import bcrypt
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
    except ImportError:
        print("Praktik 4 butuh: pip install bcrypt argon2-cffi")
        return

    PASSWORD = "admin123"

    # Daftar kata sandi umum (versi mini dari wordlist seperti rockyou.txt)
    WORDLIST = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345",
        "1234", "111111", "1234567", "dragon", "123123", "baseball", "abc123",
        "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321",
        "superman", "1qaz2wsx", "7777777", "admin123", "indonesia", "bismillah",
    ]

    def ukur(fungsi, ulang: int = 1) -> float:
        """Kembalikan rata-rata waktu (detik) satu pemanggilan fungsi."""
        mulai = time.perf_counter()
        for _ in range(ulang):
            fungsi()
        return (time.perf_counter() - mulai) / ulang

    # ------------------------------------------------------------------
    # BAGIAN 1: SHA-256 tanpa salt
    # ------------------------------------------------------------------
    garis("BAGIAN 1. SHA-256 tanpa salt")

    pengguna = {"andi": PASSWORD, "budi": PASSWORD, "citra": "Kopi!Pagi#2026"}
    print("\nIsi tabel users (password disimpan sebagai SHA-256):")
    for nama, pw in pengguna.items():
        print(f"  {nama:<6} {hashlib.sha256(pw.encode()).hexdigest()}")

    print("\nOBSERVASI:")
    print("  -> andi dan budi memiliki hash identik: penyerang langsung tahu")
    print("     keduanya memakai password yang sama.")
    print("  -> Hash deterministik dapat dicari di tabel pre-computed (rainbow table)")
    print("     tanpa menghitung ulang.")

    # ------------------------------------------------------------------
    # BAGIAN 2: SHA-256 dengan salt
    # ------------------------------------------------------------------
    garis("BAGIAN 2. SHA-256 dengan salt acak per pengguna")

    print()
    for nama, pw in pengguna.items():
        salt = os.urandom(16)
        h = hashlib.sha256(salt + pw.encode()).hexdigest()
        print(f"  {nama:<6} salt={salt.hex()[:12]}...  hash={h[:32]}...")

    waktu_sha = ukur(lambda: hashlib.sha256(os.urandom(16) + PASSWORD.encode()).digest(), 200_000)
    print(f"\nKecepatan SHA-256 (Python, 1 core CPU): ~{1 / waktu_sha:,.0f} hash/detik")
    print("GPU dengan hashcat dapat menghitung MILIARAN SHA-256 per detik.")
    print("\nOBSERVASI:")
    print("  -> Salt membuat hash andi dan budi berbeda dan menggagalkan rainbow table.")
    print("  -> Namun SHA-256 tetap terlalu cepat: penyerang tetap dapat mencoba")
    print("     miliaran tebakan per detik untuk setiap salt.")

    # ------------------------------------------------------------------
    # BAGIAN 3: bcrypt dan Argon2id
    # ------------------------------------------------------------------
    garis("BAGIAN 3. bcrypt dan Argon2id")

    pw = PASSWORD.encode()
    print("\nbcrypt, password yang sama di-hash tiga kali:")
    for i in range(3):
        print(f"  {bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode()}")
    contoh_bcrypt = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode()
    print("\nStruktur string bcrypt:")
    print(f"  {contoh_bcrypt}")
    print(f"  versi  : {contoh_bcrypt[1:3]}   (karakter ke-2 sampai 3)")
    print(f"  cost   : {contoh_bcrypt[4:6]}   (2^cost iterasi)")
    print(f"  salt   : {contoh_bcrypt[7:29]}   (22 karakter, karakter ke-8 sampai 29)")
    print(f"  hash   : {contoh_bcrypt[29:]}   (31 karakter)")

    ph = PasswordHasher()  # parameter default argon2-cffi
    contoh_argon = ph.hash(PASSWORD)
    print("\nArgon2id (argon2-cffi, parameter default):")
    print(f"  {contoh_argon}")
    print(f"  memori = {ph.memory_cost:,} KiB, iterasi = {ph.time_cost}, "
          f"paralelisme = {ph.parallelism}")

    print("\nWaktu per hash (rata-rata 3 kali):")
    waktu = {}
    for cost in (10, 12, 14):
        waktu[f"bcrypt cost {cost}"] = ukur(lambda c=cost: bcrypt.hashpw(pw, bcrypt.gensalt(rounds=c)), 3)
    waktu["Argon2id default"] = ukur(lambda: ph.hash(PASSWORD), 3)
    for nama, t in waktu.items():
        print(f"  {nama:<18} {t * 1000:>8.0f} ms   (~{t / waktu_sha:,.0f}x lebih lambat dari SHA-256)")

    print("\nVerifikasi login:")
    print(f"  bcrypt.checkpw('admin123')  -> {bcrypt.checkpw(pw, contoh_bcrypt.encode())}")
    print(f"  bcrypt.checkpw('salah123')  -> {bcrypt.checkpw(b'salah123', contoh_bcrypt.encode())}")
    print(f"  argon2 verify('admin123')   -> {ph.verify(contoh_argon, PASSWORD)}")
    try:
        ph.verify(contoh_argon, "salah123")
    except VerifyMismatchError:
        print("  argon2 verify('salah123')   -> VerifyMismatchError (ditolak)")

    print("\nOBSERVASI:")
    print("  -> Setiap kenaikan cost bcrypt sebesar 1 menggandakan waktu.")
    print("  -> Argon2id juga memakai banyak MEMORI per tebakan (memory-hard),")
    print("     sehingga serangan dengan GPU/ASIC menjadi jauh lebih mahal.")

    # ------------------------------------------------------------------
    # BAGIAN 4: Serangan kamus terhadap hash yang bocor
    # ------------------------------------------------------------------
    garis("BAGIAN 4. Serangan kamus: apakah algoritma lambat cukup?")

    salt = os.urandom(16)
    bocor_sha = hashlib.sha256(salt + pw).digest()
    bocor_bcrypt = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
    bocor_argon = ph.hash(PASSWORD)

    def _argon_cocok(w: str) -> bool:
        try:
            return ph.verify(bocor_argon, w)
        except VerifyMismatchError:
            return False

    uji = {
        "SHA-256 + salt": lambda w: hashlib.sha256(salt + w.encode()).digest() == bocor_sha,
        "bcrypt cost 12": lambda w: bcrypt.checkpw(w.encode(), bocor_bcrypt),
        "Argon2id": lambda w: _argon_cocok(w),
    }

    print(f"\nWordlist: {len(WORDLIST)} kata sandi umum. Target: hash bocor milik 'andi'.\n")
    for nama, cek in uji.items():
        mulai = time.perf_counter()
        ketemu = None
        for i, kata in enumerate(WORDLIST, 1):
            if cek(kata):
                ketemu = (i, kata)
                break
        durasi = time.perf_counter() - mulai
        print(f"  {nama:<15} ditemukan '{ketemu[1]}' pada tebakan ke-{ketemu[0]} "
              f"dalam {durasi:.3f} detik")

    print("\nEkstrapolasi untuk wordlist 14 juta kata (seukuran rockyou.txt), 1 core:")
    for nama, t in [("SHA-256 + salt", waktu_sha),
                    ("bcrypt cost 12", waktu["bcrypt cost 12"]),
                    ("Argon2id default", waktu["Argon2id default"])]:
        detik = 14_000_000 * t
        teks = f"{detik:,.0f} detik" if detik < 3600 else f"{detik / 86400:,.1f} hari"
        print(f"  {nama:<17} ~{teks}")

    print("\nOBSERVASI:")
    print("  -> Password lemah tetap ditemukan oleh SEMUA algoritma.")
    print("  -> Algoritma lambat hanya memperbesar biaya per tebakan. Keamanan")
    print("     tetap bergantung pada kekuatan password, salt unik, dan cost yang tepat.")

    # ------------------------------------------------------------------
    # BAGIAN 5: Batas 72 byte pada bcrypt
    # ------------------------------------------------------------------
    garis("BAGIAN 5. Batas input 72 byte pada bcrypt")

    pw_panjang_1 = b"A" * 72 + b"-akhiran-pertama"
    pw_panjang_2 = b"A" * 72 + b"-akhiran-berbeda"
    print(f"\nPanjang password uji: {len(pw_panjang_1)} byte")
    print(f"Versi library bcrypt: {bcrypt.__version__}")
    try:
        h = bcrypt.hashpw(pw_panjang_1, bcrypt.gensalt(rounds=4))
        sama = bcrypt.checkpw(pw_panjang_2, h)
        print("Library memotong input secara diam-diam.")
        print(f"Password lain dengan 72 byte awal yang sama diterima: {sama}")
    except ValueError as e:
        print(f"Library menolak input: ValueError: {e}")

    print("\nOBSERVASI:")
    print("  -> bcrypt hanya memproses 72 byte pertama. Versi lama memotong")
    print("     diam-diam, versi 5.0 ke atas menolak dengan ValueError.")
    print("  -> Argon2id tidak memiliki batas ini. Alasan utama OWASP memilih")
    print("     Argon2id tetap sifat memory-hard (slide 21); batas 72 byte adalah")
    print("     keterbatasan bcrypt yang wajib diketahui pengembang.")


PRAKTIK = {"1": praktik1, "2": praktik2, "3": praktik3, "4": praktik4}

if __name__ == "__main__":
    pilihan = sys.argv[1:] or sorted(PRAKTIK)
    for p in pilihan:
        if p not in PRAKTIK:
            sys.exit(f"Pilihan tidak dikenal: {p} (gunakan 1, 2, 3, atau 4)")
    for p in pilihan:
        PRAKTIK[p]()
