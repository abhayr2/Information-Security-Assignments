def blum_micali_prg(p: int, g: int, seed: int, num_bits: int) -> str:
    """ PRG based on the Discrete Logarithm Problem."""
    x_i = seed
    threshold = (p - 1) // 2
    prg_output = []
    
    for _ in range(num_bits):
        bit = '1' if x_i <= threshold else '0'
        prg_output.append(bit)
        x_i = pow(g, x_i, p)
        
    return "".join(prg_output)

def length_doubling_prg(p: int, g: int, seed: int, n_bits: int) -> tuple:
    """
    uses PRG to double the length of the seed, returning two new seeds.
    """
    # generate 2n bits
    double_length_bits = blum_micali_prg(p, g, seed, n_bits * 2)
    
    # split into left and right halves
    left_bits = double_length_bits[:n_bits]
    right_bits = double_length_bits[n_bits:]
    
    # convert bits back to integers to be used as next seeds
    # use (val % (p-1)) + 1 to ensure the new seed remains strictly between 0 and p

    left_seed = (int(left_bits, 2) % (p - 1)) + 1
    right_seed = (int(right_bits, 2) % (p - 1)) + 1
    
    return left_seed, right_seed

def ggm_prf(p: int, g: int, key: int, x: str, n_bits: int) -> str:
    """
    Evaluates the Pseudorandom Function F_k(x) using the GGM tree.
    
    Parameters:
    p (int): large prime.
    g (int): generator.
    key (int): cryptographic key (k), used as  root seed.
    x (str):  input to the PRF (a string of '0's and '1's).
    n_bits (int): the bit-length of the seeds/states.
    
    Returns:
    str:  final n-bit pseudorandom output.
    """
    current_state = key
    
    # traverse the GGM tree based on the input bits of x
    for bit in x:
        left_seed, right_seed = length_doubling_prg(p, g, current_state, n_bits)
        
        if bit == '0':
            current_state = left_seed
        elif bit == '1':
            current_state = right_seed
        else:
            raise ValueError("Input x must be a binary string.")
            
    # once we reach leaf node, do one final PRG pass to generate the output bitstring
    # or just return the binary representation of the current_state
    final_output = blum_micali_prg(p, g, current_state, n_bits)
    return final_output

# --- Example Usage ---
if __name__ == "__main__":
    P = 1019   # A prime
    G = 2      # A generator for mod P
    KEY = 42   # Our PRF key (k)
    N_BITS = 10 # Bit-length corresponding roughly to our prime P
    
    # We want to evaluate F_k(x) for different inputs
    input_1 = "101"
    input_2 = "110"
    
    output_1 = ggm_prf(P, G, KEY, input_1, N_BITS)
    output_2 = ggm_prf(P, G, KEY, input_2, N_BITS)
    
    print(f"F_k('{input_1}') = {output_1}")
    print(f"F_k('{input_2}') = {output_2}")