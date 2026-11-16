# Praktikum RSA. Key Generation, Enkripsi, dan Dekripsi

# ----------------------------
# Fungsi matematika dasar
# ----------------------------
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Mengembalikan (g, x, y) sehingga a*x + b*y = g, dengan g = gcd(a, b)"""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def mod_inverse(a, m):
    """Mencari inverse modulo: a * x = 1 (mod m)"""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Inverse modulo tidak ada untuk a={a}, m={m}")
    return x % m

# ----------------------------
# Key generation RSA
# ----------------------------
def generate_rsa_keys(p, q, e):
    """Membuat pasangan kunci RSA dari p, q, e. Untuk praktikum, bukan produksi."""
    if p == q:
        raise ValueError("p dan q tidak boleh sama")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError("e harus relatif prima terhadap phi(n)")

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key, phi

# ----------------------------
# Enkripsi / dekripsi integer
# ----------------------------
def rsa_encrypt_number(m, public_key):
    e, n = public_key
    if not (0 <= m < n):
        raise ValueError(f"Pesan integer harus di rentang 0 <= m < n ({n})")
    return pow(m, e, n)

def rsa_decrypt_number(c, private_key):
    d, n = private_key
    return pow(c, d, n)

# ----------------------------
# Demo utama
# ----------------------------
def rsa_demo(p, q, e, m):
    public_key, private_key, phi = generate_rsa_keys(p, q, e)

    print("=== RSA Key Generation ===")
    print("p =", p)
    print("q =", q)
    print("n = p * q =", p * q)
    print("phi(n) =", phi)
    print("e =", public_key[0])
    print("d =", private_key[0])
    print("public key =", public_key)
    print("private key =", private_key)

    c = rsa_encrypt_number(m, public_key)
    m2 = rsa_decrypt_number(c, private_key)

    print("\n=== RSA Encrypt/Decrypt Number ===")
    print("Plaintext number =", m)
    print("Ciphertext       =", c)
    print("Decrypted        =", m2)
    return public_key, private_key, phi

# Bagian A: program dasar
p, q, e = 61, 53, 17
public_key, private_key, phi = rsa_demo(p, q, e, 65)

# Bagian B: verifikasi matematika
d = private_key[0]
n = p * q
print("\n=== Verifikasi ===")
print("n = p x q            :", n == p * q, f"({n})")
print("phi(n) = (p-1)(q-1) :", phi == (p - 1) * (q - 1), f"({phi})")
print("gcd(e, phi(n)) = 1  :", gcd(e, phi) == 1)
print(f"({e} * {d}) % {phi}     =", (e * d) % phi)

# Bagian D: eksperimen
print("\n\n##### Eksperimen 1: m = 100 #####")
rsa_demo(61, 53, 17, 100)

print("\n\n##### Eksperimen 2: e = 7 #####")
rsa_demo(61, 53, 7, 65)

print("\n\n##### Eksperimen 3: e = 12 (tidak valid) #####")
try:
    rsa_demo(61, 53, 12, 65)
except ValueError as err:
    print("Error:", err)
