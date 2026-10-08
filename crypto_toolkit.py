"""
Classical Cryptography Toolkit
Course: Network Security | Final Year (ECM) 2026-27
Menu-driven application implementing classical ciphers.
"""
import math
import random
import string
import time

ALPHA = string.ascii_uppercase


def letters(s):
    return "".join(c for c in s.upper() if c.isalpha())


def shift_char(c, k):
    base = 65 if c.isupper() else 97
    return chr((ord(c) - base + k) % 26 + base)


# ---------------------------------------------------------------- Caesar
def caesar_key(raw, text):
    return int(raw) % 26


def caesar_enc(t, k):
    return "".join(shift_char(c, k) if c.isalpha() else c for c in t)


def caesar_dec(t, k):
    return caesar_enc(t, -k)


# -------------------------------------------------------- Monoalphabetic
def mono_key(raw, text):
    raw = raw.strip().upper()
    if not raw:
        chars = list(ALPHA)
        random.shuffle(chars)
        raw = "".join(chars)
        print("Random key generated:", raw)
    if len(raw) != 26 or set(raw) != set(ALPHA):
        raise ValueError("Key must contain all 26 letters exactly once.")
    return raw


def _sub(t, src, dst):
    table = {}
    for a, b in zip(src, dst):
        table[a] = b
        table[a.lower()] = b.lower()
    return "".join(table.get(c, c) for c in t)


def mono_enc(t, k):
    return _sub(t, ALPHA, k)


def mono_dec(t, k):
    return _sub(t, k, ALPHA)


# --------------------------------------------------------------- Playfair
def playfair_key(raw, text):
    k = letters(raw).replace("J", "I")
    if not k:
        raise ValueError("Keyword must contain letters.")
    seen = []
    for c in k + ALPHA.replace("J", ""):
        if c not in seen:
            seen.append(c)
    return seen  # 25-letter list (5x5 matrix, row-major)


def _pf_process(text, m, d):
    pos = {c: divmod(i, 5) for i, c in enumerate(m)}
    out = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:
            out += [m[r1 * 5 + (c1 + d) % 5], m[r2 * 5 + (c2 + d) % 5]]
        elif c1 == c2:
            out += [m[((r1 + d) % 5) * 5 + c1], m[((r2 + d) % 5) * 5 + c2]]
        else:
            out += [m[r1 * 5 + c2], m[r2 * 5 + c1]]
    return "".join(out)


def playfair_enc(t, m):
    t = letters(t).replace("J", "I")
    pairs, i = "", 0
    while i < len(t):
        a = t[i]
        if i + 1 < len(t) and t[i + 1] != a:
            pairs += a + t[i + 1]
            i += 2
        else:
            pairs += a + "X"
            i += 1
    return _pf_process(pairs, m, 1)


def playfair_dec(t, m):
    t = letters(t)
    if len(t) % 2:
        raise ValueError("Playfair ciphertext must have an even number of letters.")
    return _pf_process(t, m, -1)


# ------------------------------------------------------------------- Hill
def _minor(m, i, j):
    return [r[:j] + r[j + 1:] for k, r in enumerate(m) if k != i]


def _det(m):
    if len(m) == 1:
        return m[0][0]
    return sum((-1) ** j * m[0][j] * _det(_minor(m, 0, j)) for j in range(len(m)))


def hill_key(raw, text):
    k = letters(raw)
    n = int(math.isqrt(len(k)))
    if n < 2 or n * n != len(k):
        raise ValueError("Key length must be 4 (2x2) or 9 (3x3) letters.")
    m = [[ord(k[r * n + c]) - 65 for c in range(n)] for r in range(n)]
    d = _det(m) % 26
    if math.gcd(d, 26) != 1:
        raise ValueError("Key matrix is not invertible mod 26 (determinant = %d)." % d)
    return m


def _hill_inverse(m):
    n = len(m)
    d_inv = pow(_det(m) % 26, -1, 26)
    return [[(d_inv * (-1) ** (i + j) * _det(_minor(_minor_t(m), i, j))) % 26
             for j in range(n)] for i in range(n)]


def _minor_t(m):
    return [list(r) for r in zip(*m)]


def _hill_apply(t, m):
    n = len(m)
    nums = [ord(c) - 65 for c in t]
    out = ""
    for i in range(0, len(nums), n):
        block = nums[i:i + n]
        for r in range(n):
            out += chr(sum(m[r][c] * block[c] for c in range(n)) % 26 + 65)
    return out


def hill_enc(t, m):
    t = letters(t)
    while len(t) % len(m):
        t += "X"
    return _hill_apply(t, m)


def hill_dec(t, m):
    t = letters(t)
    if len(t) % len(m):
        raise ValueError("Ciphertext length must be a multiple of %d." % len(m))
    return _hill_apply(t, _hill_inverse(m))


# --------------------------------------------------------------- Vigenere
def vig_key(raw, text):
    k = letters(raw)
    if not k or not raw.strip().isalpha():
        raise ValueError("Key must contain only letters.")
    return k


def _vig(t, k, sign):
    out, i = [], 0
    for c in t:
        if c.isalpha():
            out.append(shift_char(c, sign * (ord(k[i % len(k)]) - 65)))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def vig_enc(t, k):
    return _vig(t, k, 1)


def vig_dec(t, k):
    return _vig(t, k, -1)


# ------------------------------------------------------------ One-Time Pad
def otp_key(raw, text):
    need = len(letters(text))
    raw = letters(raw)
    if not raw:
        raw = "".join(random.choice(ALPHA) for _ in range(need))
        print("Random one-time key generated:", raw)
    if len(raw) < need:
        raise ValueError("Key must be at least as long as the text (%d letters)." % need)
    return raw


def otp_enc(t, k):
    return _vig(t, k, 1)


def otp_dec(t, k):
    return _vig(t, k, -1)


# -------------------------------------------------------------- Rail Fence
def rail_key(raw, text):
    r = int(raw)
    if r < 2:
        raise ValueError("Number of rails must be at least 2.")
    return r


def _rail_order(n, r):
    cycle = 2 * (r - 1)
    rows = [(i % cycle) if (i % cycle) < r else cycle - (i % cycle) for i in range(n)]
    return sorted(range(n), key=lambda i: rows[i])


def rail_enc(t, r):
    return "".join(t[i] for i in _rail_order(len(t), r))


def rail_dec(t, r):
    out = [""] * len(t)
    for j, i in enumerate(_rail_order(len(t), r)):
        out[i] = t[j]
    return "".join(out)


# ---------------------------------------------------- Columnar Transposition
def col_key(raw, text):
    k = letters(raw)
    if len(k) < 2:
        raise ValueError("Keyword must have at least 2 letters.")
    return k


def _col_order(k):
    return sorted(range(len(k)), key=lambda i: (k[i], i))


def col_enc(t, k):
    t = letters(t)
    while len(t) % len(k):
        t += "X"
    return "".join(t[c::len(k)] for c in _col_order(k))


def col_dec(t, k):
    t = letters(t)
    if len(t) % len(k):
        raise ValueError("Ciphertext length must be a multiple of the key length.")
    rows = len(t) // len(k)
    cols = {}
    for n, c in enumerate(_col_order(k)):
        cols[c] = t[n * rows:(n + 1) * rows]
    return "".join(cols[c][r] for r in range(rows) for c in range(len(k)))


# ------------------------------------------------------------------ Registry
CIPHERS = {
    "1": ("Caesar Cipher", caesar_key, caesar_enc, caesar_dec, "Integer shift, e.g. 5", "3"),
    "2": ("Monoalphabetic Cipher", mono_key, mono_enc, mono_dec, "26-letter key (blank = random)", ""),
    "3": ("Playfair Cipher", playfair_key, playfair_enc, playfair_dec, "Keyword, e.g. MONARCHY", "MONARCHY"),
    "4": ("Hill Cipher", hill_key, hill_enc, hill_dec, "4 or 9 letters, e.g. GYBNQKURP", "GYBNQKURP"),
    "5": ("Vigenere Cipher", vig_key, vig_enc, vig_dec, "Keyword, e.g. LEMON", "LEMON"),
    "6": ("One-Time Pad", otp_key, otp_enc, otp_dec, "Random key >= text length (blank = random)", ""),
    "7": ("Rail Fence Cipher", rail_key, rail_enc, rail_dec, "Number of rails, e.g. 3", "3"),
    "8": ("Columnar Transposition", col_key, col_enc, col_dec, "Keyword, e.g. ZEBRAS", "ZEBRAS"),
}

MENU = """
==========================================
    CLASSICAL CRYPTOGRAPHY TOOLKIT
==========================================
SUBSTITUTION CIPHERS
 1. Caesar Cipher
 2. Monoalphabetic Cipher
 3. Playfair Cipher
 4. Hill Cipher
 5. Vigenere (Polyalphabetic) Cipher
 6. One-Time Pad
TRANSPOSITION CIPHERS
 7. Rail Fence Cipher
 8. Columnar Transposition Cipher
UTILITY MODULES
 9. Compare Algorithms
10. Encrypt Text File
11. Decrypt Text File
12. Help
13. Exit
==========================================
"""


def run_cipher(choice):
    name, keyf, enc, dec, hint, _ = CIPHERS[choice]
    print("\n--- %s ---" % name)
    text = input("Enter Plaintext : ")
    if not text.strip():
        raise ValueError("Plaintext cannot be empty.")
    key = keyf(input("Enter Key (%s) : " % hint), text)
    t0 = time.perf_counter()
    ct = enc(text, key)
    t1 = time.perf_counter()
    pt = dec(ct, key)
    t2 = time.perf_counter()
    print("Encrypted Text : ", ct)
    print("Decrypted Text : ", pt)
    print("Encryption time: %.6f ms | Decryption time: %.6f ms" % ((t1 - t0) * 1000, (t2 - t1) * 1000))


def compare():
    text = input("Enter Plaintext to compare : ")
    if not text.strip():
        raise ValueError("Plaintext cannot be empty.")
    print("\n%-24s %-12s %s" % ("Cipher", "Time (ms)", "Ciphertext"))
    print("-" * 70)
    for c, (name, keyf, enc, dec, _, default) in CIPHERS.items():
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            key = keyf(default, text)
        t0 = time.perf_counter()
        ct = enc(text, key)
        ms = (time.perf_counter() - t0) * 1000
        print("%-24s %-12.6f %s" % (name, ms, ct))
    print("(Default demo keys used; random keys for Monoalphabetic and One-Time Pad.)")


def pick_cipher():
    for c, v in CIPHERS.items():
        print(" %s. %s" % (c, v[0]))
    c = input("Select cipher (1-8) : ").strip()
    if c not in CIPHERS:
        raise ValueError("Invalid cipher selection.")
    return c


def file_op(encrypt):
    c = pick_cipher()
    name, keyf, enc, dec, hint, _ = CIPHERS[c]
    src = input("Input file path  : ").strip()
    dst = input("Output file path : ").strip()
    try:
        with open(src, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise ValueError("Cannot read file: %s" % e)
    key = keyf(input("Enter Key (%s) : " % hint), text)
    t0 = time.perf_counter()
    result = enc(text, key) if encrypt else dec(text, key)
    ms = (time.perf_counter() - t0) * 1000
    with open(dst, "w", encoding="utf-8") as f:
        f.write(result)
    print("Done (%s, %.4f ms). Saved to %s" % (name, ms, dst))


HELP = """
HELP
 1 Caesar        key: integer (shift)
 2 Monoalphabetic key: 26 unique letters (leave blank for a random key)
 3 Playfair      key: keyword (J is treated as I; X is used as filler)
 4 Hill          key: 4 letters (2x2) or 9 letters (3x3); matrix must be invertible mod 26
 5 Vigenere      key: alphabetic keyword
 6 One-Time Pad  key: random letters, at least as long as the text (blank = random)
 7 Rail Fence    key: number of rails (>= 2)
 8 Columnar      key: keyword (padded with X if needed)
 9 Compare       runs every cipher on one plaintext with demo keys
10/11 File       encrypt or decrypt a text file with a chosen cipher and key
Note: Playfair, Hill and Columnar work on letters only and may add filler X.
"""


def main():
    while True:
        print(MENU)
        choice = input("Enter your Choice : ").strip()
        try:
            if choice in CIPHERS:
                run_cipher(choice)
            elif choice == "9":
                compare()
            elif choice == "10":
                file_op(True)
            elif choice == "11":
                file_op(False)
            elif choice == "12":
                print(HELP)
            elif choice == "13":
                print("Thank you for using the toolkit. Goodbye!")
                break
            else:
                print("Invalid choice. Please enter a number from 1 to 13.")
        except ValueError as e:
            print("Error:", e)
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
