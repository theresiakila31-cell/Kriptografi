# Minggu 4. Mode Operasi Block Cipher (ECB vs CBC)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# ============================================================
# Praktikum 4A. Demo konsep ECB leakage
# ============================================================
def toy_block_encrypt(block):
    return block[::-1] + "|X"

def ecb_encrypt_demo(message, block_size=4):
    blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]
    ciphertext_blocks = [toy_block_encrypt(block) for block in blocks]
    return blocks, ciphertext_blocks

print("=== Praktikum 4A ===")
message = "AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB"
blocks, cblocks = ecb_encrypt_demo(message, block_size=4)

print("=== Plaintext blocks ===")
for i, b in enumerate(blocks, 1):
    print(f"Block {i}: {b}")

print("\n=== Ciphertext blocks ===")
for i, c in enumerate(cblocks, 1):
    print(f"Block {i}: {c}")


# ============================================================
# Praktikum 4B. AES-ECB asli
# ============================================================
print("\n=== Praktikum 4B ===")
key = b'1234567890abcdef'

def aes_ecb_demo(plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, 16))

    print("Plaintext      :", plaintext)
    print("Ciphertext hex :", ciphertext.hex())

    print("\n=== Blok ciphertext ===")
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    for i, block in enumerate(blocks, 1):
        print(f"Block {i}: {block.hex()}")

    print("\nApakah blok 1 == blok 2?", blocks[0] == blocks[1])

# Plaintext asli: blok 1 dan 2 sama
aes_ecb_demo(b'AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB')

# Plaintext diubah: blok 1 dan 2 berbeda
print("\n--- Plaintext diubah ---")
aes_ecb_demo(b'AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD')


# ============================================================
# Praktikum 4C. ECB vs CBC
# ============================================================
print("\n=== Praktikum 4C ===")
plaintext = b'AAAAAAAABBBBBBBBAAAAAAAABBBBBBBB'

ecb_cipher = AES.new(key, AES.MODE_ECB)
ecb_ct = ecb_cipher.encrypt(pad(plaintext, 16))

iv = get_random_bytes(16)
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
cbc_ct = cbc_cipher.encrypt(pad(plaintext, 16))

print("ECB ciphertext:", ecb_ct.hex())
print("CBC ciphertext:", cbc_ct.hex())
