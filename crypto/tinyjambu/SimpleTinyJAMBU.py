from tinyjambu import encrypt 

class SimpleTinyJAMBU:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def encrypt(self, plaintext):
        # Encrypt using TinyJAMBU
        ciphertext = encrypt(plaintext, self.key, self.nonce)
        return ciphertext