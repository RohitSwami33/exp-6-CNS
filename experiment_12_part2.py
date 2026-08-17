from math import gcd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def euclidean_gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd_value, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd_value, x, y


def modular_inverse(a, m):
    gcd_value, x, _ = extended_gcd(a, m)
    if gcd_value != 1:
        return None
    return x % m


def affine_encrypt(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Invalid key: gcd(a,26) must be 1.")
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            x = ord(char) - base
            encrypted = (a * x + b) % 26
            result += chr(encrypted + base)
        else:
            result += char
    return result


def affine_decrypt(text, a, b):
    inverse_a = modular_inverse(a, 26)
    if inverse_a is None:
        raise ValueError("No multiplicative inverse exists.")
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            y = ord(char) - base
            decrypted = (inverse_a * (y - b)) % 26
            result += chr(decrypted + base)
        else:
            result += char
    return result


def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            encrypted = (ord(char) - base + shift) % 26
            result += chr(encrypted + base)
            key_index += 1
        else:
            result += char
    return result


def vigenere_decrypt(text, key):
    key = key.upper()
    result = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted = (ord(char) - base - shift) % 26
            result += chr(decrypted + base)
            key_index += 1
        else:
            result += char
    return result


def crt(remainders, moduli):
    product = 1
    for modulus in moduli:
        product *= modulus

    result = 0
    for remainder, modulus in zip(remainders, moduli):
        partial_product = product // modulus
        inverse = modular_inverse(partial_product % modulus, modulus)
        if inverse is None:
            raise ValueError("CRT requires suitable coprime moduli.")
        result += remainder * partial_product * inverse

    return result % product


def aes_encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv, ciphertext


def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()


def main():
    print("=" * 70)
    print("DESIGN AND ANALYSIS OF A SECURE ENCRYPTION SCHEME")
    print("=" * 70)

    plaintext = "HELLO WORLD"

    # 1. Caesar Cipher
    shift = 3
    caesar_ciphertext = caesar_encrypt(plaintext, shift)
    caesar_decrypted = caesar_decrypt(caesar_ciphertext, shift)

    print("\n" + "-" * 70)
    print("1. CAESAR CIPHER")
    print("-" * 70)
    print("Plaintext :", plaintext)
    print("Key :", shift)
    print("Ciphertext:", caesar_ciphertext)
    print("Decrypted :", caesar_decrypted)

    # 2. Euclidean Algorithm
    print("\n" + "-" * 70)
    print("2. EUCLIDEAN ALGORITHM")
    print("-" * 70)
    a = 35
    b = 26
    gcd_result = euclidean_gcd(a, b)
    print(f"GCD({a}, {b}) = {gcd_result}")

    # 3. Affine Cipher + modular inverse
    print("\n" + "-" * 70)
    print("3. AFFINE CIPHER")
    print("-" * 70)
    a = 5
    b = 8
    print(f"gcd({a}, 26) =", gcd(a, 26))
    inverse = modular_inverse(a, 26)
    print(f"Multiplicative inverse of {a} modulo 26 =", inverse)
    affine_ciphertext = affine_encrypt(plaintext, a, b)
    affine_decrypted = affine_decrypt(affine_ciphertext, a, b)
    print("Plaintext :", plaintext)
    print("Keys :", a, b)
    print("Ciphertext:", affine_ciphertext)
    print("Decrypted :", affine_decrypted)

    # 4. Vigenere Cipher
    print("\n" + "-" * 70)
    print("4. VIGENERE CIPHER")
    print("-" * 70)
    vigenere_key = "KEY"
    vigenere_ciphertext = vigenere_encrypt(plaintext, vigenere_key)
    vigenere_decrypted = vigenere_decrypt(vigenere_ciphertext, vigenere_key)
    print("Plaintext :", plaintext)
    print("Key :", vigenere_key)
    print("Ciphertext:", vigenere_ciphertext)
    print("Decrypted :", vigenere_decrypted)

    # 5. Congruence Relation
    print("\n" + "-" * 70)
    print("5. CONGRUENCE RELATION")
    print("-" * 70)
    x = 29
    y = 3
    m = 26
    print(f"{x} mod {m} =", x % m)
    if (x - y) % m == 0:
        print(f"{x} ≡ {y} (mod {m})")
    else:
        print(f"{x} is not congruent to {y} modulo {m}")

    # 6. Fermat's Little Theorem
    print("\n" + "-" * 70)
    print("6. FERMAT'S LITTLE THEOREM")
    print("-" * 70)
    a = 3
    p = 7
    result = pow(a, p - 1, p)
    print(f"{a}^({p}-1) mod {p} =", result)
    if result == 1:
        print("Fermat's Little Theorem verified.")

    # 7. Chinese Remainder Theorem
    print("\n" + "-" * 70)
    print("7. CHINESE REMAINDER THEOREM")
    print("-" * 70)
    remainders = [2, 3, 2]
    moduli = [3, 5, 7]
    crt_result = crt(remainders, moduli)
    print("Given equations:")
    print("x ≡ 2 (mod 3)")
    print("x ≡ 3 (mod 5)")
    print("x ≡ 2 (mod 7)")
    print("\nCRT Solution: x =", crt_result)
    print("\nVerification:")
    for r, mod in zip(remainders, moduli):
        print(f"x mod {mod} = {crt_result % mod}")

    # 8. AES-CBC
    print("\n" + "-" * 70)
    print("8. AES-CBC")
    print("-" * 70)
    aes_key = b"0123456789ABCDEF"
    aes_iv, aes_ciphertext = aes_encrypt(plaintext, aes_key)
    aes_decrypted = aes_decrypt(aes_iv, aes_ciphertext, aes_key)
    print("Plaintext :", plaintext)
    print("AES Key :", aes_key.decode())
    print("IV :", aes_iv.hex())
    print("Ciphertext:", aes_ciphertext.hex())
    print("Decrypted :", aes_decrypted)

    # Final verification
    print("\n" + "=" * 70)
    print("FINAL VERIFICATION")
    print("=" * 70)
    tests = [
        ("Caesar Cipher", caesar_decrypted == plaintext),
        ("Affine Cipher", affine_decrypted == plaintext),
        ("Vigenere Cipher", vigenere_decrypted == plaintext),
        ("AES-CBC", aes_decrypted == plaintext),
    ]

    all_passed = True
    for test_name, test_result in tests:
        if test_result:
            print(f"{test_name}: PASS")
        else:
            print(f"{test_name}: FAIL")
            all_passed = False

    if all_passed:
        print("\nAll encryption/decryption tests completed successfully.")
    else:
        print("\nSome tests failed.")

    print("\n" + "=" * 70)
    print("CONCLUSION")
    print("=" * 70)
    print("The experiment demonstrates the use of classical and modern")
    print("cryptographic techniques.")
    print("Caesar, Affine and Vigenere ciphers demonstrate substitution")
    print("and poly-alphabetic encryption.")
    print("The Euclidean algorithm is used to determine GCD and supports")
    print("the calculation of modular inverses.")
    print("Congruence, Fermat's Little Theorem and the Chinese Remainder")
    print("Theorem demonstrate important mathematical foundations used")
    print("in cryptography.")
    print("AES-CBC demonstrates a modern symmetric-key encryption method.")
    print("The successful decryption confirms the correctness of the")
    print("implemented encryption and decryption procedures.")


if __name__ == "__main__":
    main()
