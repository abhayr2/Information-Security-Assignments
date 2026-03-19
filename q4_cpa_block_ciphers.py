import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CustomCPAEncryption:
    def __init__(self, primitive="AES", mode="RC"):
        self.primitive = primitive.upper()
        self.mode = mode.upper()
        
        if self.primitive == "AES":
            self.block_size = 16 
            self.algo_class = algorithms.AES
        elif self.primitive == "3DES":
            self.block_size = 8  
            self.algo_class = algorithms.TripleDES
        else:
            raise ValueError("Primitive must be AES or 3DES")

    def _xor_bytes(self, b1: bytes, b2: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(b1, b2))

    def _pad(self, data: bytes) -> bytes:
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """Removes PKCS7 padding."""
        pad_len = data[-1]
        return data[:-pad_len]

    def _evaluate_prf(self, key: bytes, block: bytes) -> bytes:
        """AES Encryption (Forward direction)."""
        cipher = Cipher(self.algo_class(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def _evaluate_prf_inverse(self, key: bytes, block: bytes) -> bytes:
        """AES Decryption (Reverse direction - only needed for CBC)."""
        cipher = Cipher(self.algo_class(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(block) + decryptor.finalize()

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        iv = os.urandom(self.block_size)
        
        if self.mode == "CBC":
            return iv, self._encrypt_cbc(key, iv, plaintext)
        elif self.mode == "OFB":
            return iv, self._stream_mode_logic(key, iv, plaintext, "OFB")
        elif self.mode == "RC":
            return iv, self._stream_mode_logic(key, iv, plaintext, "RC")
        elif self.mode == "LD":
            return iv, self._stream_mode_logic(key, iv, plaintext, "LD")
        else:
            raise ValueError("Unsupported Mode")

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypts the ciphertext back to the original message."""
        if self.mode == "CBC":
            return self._decrypt_cbc(key, iv, ciphertext)
        elif self.mode in ["OFB", "RC", "LD"]:
            # for stream modes, decryption is the exact same operation as encryption
            return self._stream_mode_logic(key, iv, ciphertext, self.mode)
        else:
            raise ValueError("Unsupported Mode")

    #  Mode Logic

    def _encrypt_cbc(self, key: bytes, iv: bytes, pt: bytes) -> bytes:
        pt_padded = self._pad(pt)
        ciphertext = b""
        prev_c = iv
        for i in range(0, len(pt_padded), self.block_size):
            block = pt_padded[i:i+self.block_size]
            c_i = self._evaluate_prf(key, self._xor_bytes(block, prev_c))
            ciphertext += c_i
            prev_c = c_i
        return ciphertext

    def _decrypt_cbc(self, key: bytes, iv: bytes, ct: bytes) -> bytes:
        plaintext_padded = b""
        prev_c = iv
        for i in range(0, len(ct), self.block_size):
            block = ct[i:i+self.block_size]
            decrypted_block = self._evaluate_prf_inverse(key, block)
            plaintext_padded += self._xor_bytes(decrypted_block, prev_c)
            prev_c = block
        return self._unpad(plaintext_padded)

    def _stream_mode_logic(self, key: bytes, iv: bytes, data: bytes, mode: str) -> bytes:
        """Handles both encryption and decryption for OFB, RC, and LD."""
        output = bytearray()
        current_state = iv
        zero_mask = b'\x00' * self.block_size
        ff_mask = b'\xFF' * self.block_size
        
        for i in range(len(data)):
            if i % self.block_size == 0:
                if mode == "OFB":
                    current_state = self._evaluate_prf(key, current_state)
                    pad = current_state
                elif mode == "RC":
                    counter_block = (int.from_bytes(iv, 'big') + (i // self.block_size)) % (2**(self.block_size * 8))
                    pad = self._evaluate_prf(key, counter_block.to_bytes(self.block_size, 'big'))
                elif mode == "LD":
                    pad = self._evaluate_prf(key, self._xor_bytes(current_state, ff_mask))
                    current_state = self._evaluate_prf(key, self._xor_bytes(current_state, zero_mask))
            
            output.append(data[i] ^ pad[i % self.block_size])
            
        return bytes(output)

# --- Interactive Example Usage ---
if __name__ == "__main__":
    # random 16-byte (128-bit) key for AES
    KEY_AES = os.urandom(16) 
    
    print("--- Complete CPA Encryption & Decryption Suite ---")
    
    #  user input
    user_input = input("\nEnter the secret message you want to encrypt: ")
    message = user_input.encode('utf-8')
    
    # mode selection
    print("\nAvailable Modes: CBC, OFB, RC, LD")
    while True:
        selected_mode = input("Select a mode: ").strip().upper()
        if selected_mode in ["CBC", "OFB", "RC", "LD"]:
            break
        print("Invalid choice. Please select from CBC, OFB, RC, or LD.")
        
    scheme = CustomCPAEncryption(primitive="AES", mode=selected_mode)
    
    # CPA Security Test (encrypting the same message twice)
    print("\n[+] Testing CPA Security (Double Encryption)...")
    iv1, ct1 = scheme.encrypt(KEY_AES, message)
    iv2, ct2 = scheme.encrypt(KEY_AES, message)
    
    print(f"\n  Encryption 1:")
    print(f"    IV:          {iv1.hex()}")
    print(f"    Ciphertext:  {ct1.hex()}")
    
    print(f"\n  Encryption 2:")
    print(f"    IV:          {iv2.hex()}")
    print(f"    Ciphertext:  {ct2.hex()}")
    
    if ct1 != ct2:
        print("CPA Check: Passed (Ciphertexts are unique)")
    else:
        print("CPA Check: Failed (Ciphertexts are identical)")

    #  Correctness Test (Decrypting back to plaintext)
    print("\n[+] Testing Correctness (Decryption)...")
    try:
        decrypted_bytes = scheme.decrypt(KEY_AES, iv1, ct1)
        decrypted_message = decrypted_bytes.decode('utf-8')
        print(f"Recovered Text: {decrypted_message}")
        
        if decrypted_message == user_input:
            print(" Correctness Check: Passed (Matches original input)")
        else:
            print("  Correctness Check: Failed (Does not match input)")
    except Exception as e:
        print(f"Correctness Check: Failed with error: {e}")