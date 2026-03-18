import secrets

# Previous PRG and PRF Implementations 
def blum_micali_prg(p: int, g: int, seed: int, num_bits: int) -> str:
    x_i = seed
    threshold = (p - 1) // 2
    prg_output = []
    for _ in range(num_bits):
        prg_output.append('1' if x_i <= threshold else '0')
        x_i = pow(g, x_i, p)
    return "".join(prg_output)

def length_doubling_prg(p: int, g: int, seed: int, n_bits: int) -> tuple:
    double_length_bits = blum_micali_prg(p, g, seed, n_bits * 2)
    left_bits, right_bits = double_length_bits[:n_bits], double_length_bits[n_bits:]
    left_seed = (int(left_bits, 2) % (p - 1)) + 1
    right_seed = (int(right_bits, 2) % (p - 1)) + 1
    return left_seed, right_seed

def ggm_prf(p: int, g: int, key: int, x: str, n_bits: int) -> str:
    current_state = key
    for bit in x:
        left_seed, right_seed = length_doubling_prg(p, g, current_state, n_bits)
        current_state = left_seed if bit == '0' else right_seed
    return blum_micali_prg(p, g, current_state, n_bits)

#  New CPA Encryption Scheme 

def xor_bitstrings(a: str, b: str) -> str:
    """XORs two binary strings of the same length."""
    if len(a) != len(b):
        raise ValueError("Bitstrings must be of the same length to XOR.")
    return "".join('1' if bit_a != bit_b else '0' for bit_a, bit_b in zip(a, b))

def generate_random_r(n_bits: int) -> str:
    """Generates a cryptographically secure random n-bit string."""
    r_int = secrets.randbits(n_bits)
    return format(r_int, f'0{n_bits}b')

def encrypt_cpa(p: int, g: int, key: int, message: str, n_bits: int) -> tuple[str, str]:
    """
    Encrypts a single-block message using the scheme: C = <r, F_k(r) XOR m>
    """
    if len(message) != n_bits:
        raise ValueError(f"Message length must exactly match the block size ({n_bits} bits).")

    #  pick a random bitstring 'r' of length n_bits
    r = generate_random_r(n_bits)
    
    #  evaluate the PRF to create the pseudorandom pad: F_k(r)
    pad = ggm_prf(p, g, key, r, n_bits)
    
    #  mask the message with the pad
    c = xor_bitstrings(pad, message)
    
    #  return the ciphertext tuple <r, c>
    return r, c

def decrypt_cpa(p: int, g: int, key: int, r: str, c: str, n_bits: int) -> str:
    """
    Decrypts the ciphertext tuple <r, c> back into the message.
    """
    # 1. Re-evaluate the PRF using the provided 'r' to recreate the pad: F_k(r)
    pad = ggm_prf(p, g, key, r, n_bits)
    
    # 2. Unmask the message by XORing the pad with the ciphertext
    message = xor_bitstrings(pad, c)
    
    return message

# --- Example Usage ---
if __name__ == "__main__":
    P = 1019   # prime
    G = 2      # generator
    KEY = 42   # secret Key (k)
    N_BITS = 8 # block size (keep small for testing due to GGM overhead!)
    
    # message must be exactly N_BITS long for this specific construction
    plaintext = input(f"Enter a binary message of length {N_BITS} bits: ")
    
    print(f"Original Message: {plaintext}\n")
    
    # encrypt the same message twice to demonstrate CPA security (different ciphertexts)
    r1, c1 = encrypt_cpa(P, G, KEY, plaintext, N_BITS)
    print(f"Encryption 1:")
    print(f"  Random r:   {r1}")
    print(f"  Ciphertext: {c1}")
    
    r2, c2 = encrypt_cpa(P, G, KEY, plaintext, N_BITS)
    print(f"\nEncryption 2:")
    print(f"  Random r:   {r2}")
    print(f"  Ciphertext: {c2}")
    
    # decrypt to verify
    decrypted_message = decrypt_cpa(P, G, KEY, r1, c1, N_BITS)
    print(f"\nDecrypted Message (from Enc 1): {decrypted_message}")
    
    assert plaintext == decrypted_message, "Decryption failed!"