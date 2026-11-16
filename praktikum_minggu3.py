# Minggu 3. Modulo dan Inverse
# ============================================================
# Praktikum 3A. Modulo arithmetic
# ============================================================
def modulo_demo(a, n):
    q = a // n
    r = a % n
    print(f"{a} mod {n} = {r} karena {a} = {q} x {n} + {r}")

print("=== Praktikum 3A ===")
modulo_demo(29, 7)
modulo_demo(100, 12)
modulo_demo(17, 5)
modulo_demo(45, 6)  


# ============================================================
# Praktikum 3B. Inverse modulo
# ============================================================
def mod_inverse(a, n):
    for x in range(1, n):
        if (a * x) % n == 1:
            return x
    return None

print("\n=== Praktikum 3B ===")
tests = [(3, 26), (5, 26), (7, 26), (2, 26), (11, 26)] 

for a, n in tests:
    inv = mod_inverse(a, n)
    print(f"inverse({a}) mod {n} = {inv}")

# Verifikasi dengan perkalian: (a * inverse) mod n harus = 1
print("\nVerifikasi:")
for a, n in tests:
    inv = mod_inverse(a, n)
    if inv is not None:
        print(f"{a} x {inv} = {a * inv}, {a * inv} mod {n} = {(a * inv) % n}")
    else:
        print(f"{a} tidak punya inverse mod {n}")


# ============================================================
# Praktikum 3C. Multiplicative cipher
# ============================================================
def multiplicative_encrypt(text, key):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            y = (x * key) % 26
            result += chr(y + base)
        else:
            result += ch
    return result

def multiplicative_decrypt(text, key):
    inv = mod_inverse(key, 26)
    if inv is None:
        raise ValueError("Key tidak punya inverse modulo 26")

    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - base
            x = (y * inv) % 26
            result += chr(x + base)
        else:
            result += ch
    return result

print("\n=== Praktikum 3C ===")
plaintext = "HELLO"

for key in [3, 5, 7]:
    ciphertext = multiplicative_encrypt(plaintext, key)
    decrypted = multiplicative_decrypt(ciphertext, key)
    print(f"\nKey = {key}")
    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Decrypted :", decrypted)

# Percobaan key = 2 (tidak valid, gcd(2, 26) = 2)
print("\nKey = 2")
ciphertext = multiplicative_encrypt(plaintext, 2)
print("Plaintext :", plaintext)
print("Ciphertext:", ciphertext)
try:
    print("Decrypted :", multiplicative_decrypt(ciphertext, 2))
except ValueError as e:
    print("Error     :", e)
