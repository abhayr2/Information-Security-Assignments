import hashlib
import os

class CustomHMAC:
    def __init__(self, hash_algorithm=hashlib.sha256):
        """
        Initializes the HMAC scheme.
        SHA-256 - block size of 64 bytes.
        """
        self.hash_algorithm = hash_algorithm
        self.block_size = 64 # 512 bits for SHA-256
        
        # standard HMAC padding constants (RFC 2104)
        self.IPAD = bytes([0x36] * self.block_size)
        self.OPAD = bytes([0x5c] * self.block_size)

    def _xor_bytes(self, b1: bytes, b2: bytes) -> bytes:
        """XORs two byte strings of the same length."""
        return bytes(x ^ y for x, y in zip(b1, b2))

    def _prepare_key(self, key: bytes) -> bytes:
        """
        Ensures the key is exactly the length of the block size (64 bytes).
        - If too long: Hash it down.
        - If too short: Pad it with zeros on the right.
        """
        if len(key) > self.block_size:
            key = self.hash_algorithm(key).digest()
            
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
            
        return key

    def generate_mac(self, key: bytes, message: bytes) -> bytes:
        """
        Generates the HMAC tag for a given message.
        Formula: H( (K XOR opad) || H( (K XOR ipad) || message ) )
        """
        standardized_key = self._prepare_key(key)
        
        # create inner and outer keys
        inner_key_pad = self._xor_bytes(standardized_key, self.IPAD)
        outer_key_pad = self._xor_bytes(standardized_key, self.OPAD)
        
        # perform the inner hash: H( (K XOR ipad) || message )
        inner_hash = self.hash_algorithm(inner_key_pad + message).digest()
        
        # perform the outer hash: H( (K XOR opad) || InnerHash )
        final_mac = self.hash_algorithm(outer_key_pad + inner_hash).digest()
        
        return final_mac

    def verify_mac(self, key: bytes, message: bytes, received_mac: bytes) -> bool:
        """
        Verifies a message's authenticity by re-computing the MAC and comparing it.
        """
        expected_mac = self.generate_mac(key, message)
        
        # constant-time comparison to prevent timing attacks
        return hmac_compare_digest(expected_mac, received_mac)

def hmac_compare_digest(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    (Python's secrets.compare_digest does exactly this).
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

if __name__ == "__main__":
    # sender and receiver must share this secret key
    SHARED_SECRET_KEY = b"SuperSecretKey_12345"
    
    print("--- Custom HMAC-SHA256 Authentication Suite ---")
    
    mac_scheme = CustomHMAC()
    
    #  user input
    user_input = input("\nEnter the message you want to authenticate: ")
    message = user_input.encode('utf-8')
    
    #  generate the MAC (done by the Sender)
    print("\n[+] Generating MAC...")
    tag = mac_scheme.generate_mac(SHARED_SECRET_KEY, message)
    print(f"    Message: {message.decode('utf-8')}")
    print(f"    MAC Tag: {tag.hex()}")
    
    # simulate successful verification (done by the Receiver)
    print("\n[+] Receiver Verification (Untampered Message)...")
    is_valid = mac_scheme.verify_mac(SHARED_SECRET_KEY, message, tag)
    if is_valid:
        print("Verification Passed: The message is authentic and untampered.")
    else:
        print("Verification Failed.")
        
    # simulate a tampered Message (attacker flips a bit in transit)
    print("\n[+] Receiver Verification (Tampered Message)...")
    tampered_message = message + b" (attacker added this)"
    print(f"    Received Message: {tampered_message.decode('utf-8', errors='ignore')}")
    print(f"    Received MAC Tag: {tag.hex()}")
    
    is_valid_tampered = mac_scheme.verify_mac(SHARED_SECRET_KEY, tampered_message, tag)
    if is_valid_tampered:
        print("Verification Passed.")
    else:
        print("Verification Failed: Alert! The message was tampered with in transit or the MAC is forged.")