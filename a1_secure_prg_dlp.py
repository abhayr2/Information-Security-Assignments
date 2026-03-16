def blum_micali_prg(p: int, g: int, seed: int, num_bits: int) -> str:
    """
    Generates a provably secure pseudorandom bit sequence using the Blum-Micali algorithm.
    
    Parameters:
    p (int): A large prime number.
    g (int): A generator for the multiplicative group modulo p.
    seed (int): The initial secret seed (x_0), where 0 < seed < p.
    num_bits (int): The length of the desired pseudorandom bit string.
    
    Returns:
    str: A string of pseudorandom bits.
    """
    if seed <= 0 or seed >= p:
        raise ValueError("Seed must be strictly between 0 and p.")
        
    x_i = seed
    threshold = (p - 1) // 2
    prg_output = []
    
    for _ in range(num_bits):
        # 1. extract the hard-core bit
        # x_i <= threshold, output '1', else '0'

        bit = '1' if x_i <= threshold else '0'
        prg_output.append(bit)
        
        # 2. compute  next state using modular exponentiation
        x_i = pow(g, x_i, p)
        
    # concatenate bits to form the final pseudorandom string
    return "".join(prg_output)

# --- example ---
if __name__ == "__main__":
    #  'p': massive prime (e.g., 2048 bits) 
    #  'g': primitive root modulo p
    # using small safe prime
    
    P = 1019   
    G = 2      
    SEED = 42  # Initial secret seed
    BITS_TO_GENERATE = 32
    
    random_bits = blum_micali_prg(P, G, SEED, BITS_TO_GENERATE)
    
    print(f"Prime (p): {P}")
    print(f"Generator (g): {G}")
    print(f"Seed (x_0): {SEED}")
    print(f"Generated {BITS_TO_GENERATE}-bit PRG stream: {random_bits}")