import numpy as np
import os
from .tinyjambu.tinyjambu import encrypt as tinyjambu_encrypt, SimpleTinyJAMBU
from pypuf.pypuf.simulation import Simulation  # Base class for PUF simulation

# Define a dictionary that maps crypto strings to the corresponding encryption functions
crypto_functions = {
    "tinyjambu": lambda cipher, data: cipher.encrypt(data)
    # Add other crypto mappings here as needed, e.g., "another_crypto": another_crypto_encrypt_function
}

class CryptoPUF(Simulation):
    def __init__(self, challenge_length: int, key: str, nonce: str, crypto: str = 'tinyjambu', seed: int = None):
        print(f"Initializing CryptoPUF based on {crypto} crypto core...")
        self._challenge_length = challenge_length
        self._response_length = 1  # Set response length to 1, as we want only 1-bit responses
        self.tinyjambu_cipher = SimpleTinyJAMBU(key=key, nonce=nonce)
        self.crypto = crypto
        if seed:
            np.random.seed(seed)

    @property
    def challenge_length(self) -> int:
        return self._challenge_length

    @property
    def response_length(self) -> int:
        return self._response_length

    def eval(self, challenges: np.ndarray) -> np.ndarray:
        """Evaluate the PUF on a list of given challenges."""
        responses = []
        crypto_path = os.path.join(os.path.dirname(__file__), self.crypto)
        
        # Ensure the selected crypto core is supported
        if self.crypto not in crypto_functions:
            raise ValueError(f"Unsupported crypto core: {self.crypto}")

        for challenge in challenges:
            # Convert the challenge from {-1, 1} to {0, 1}
            challenge_binary = 0.5 * (challenge + 1)  # -1 -> 0, 1 -> 1
            # Convert the binary challenge to bytes
            challenge_bytes = np.packbits(challenge_binary.astype(np.uint8)).tobytes()
            
            # Check if `crypto` is a directory and use the mapped function
            if os.path.isdir(crypto_path):
                encrypted_output = crypto_functions[self.crypto](self.tinyjambu_cipher, challenge_bytes)
            else:
                raise ValueError("Only supporting tinyjambu in the specified directory for now.")

            # Convert the encrypted output to binary array (128-bit response)
            encrypted_response = np.unpackbits(np.frombuffer(encrypted_output, dtype=np.uint8))
            # Extract the 65th bit (index 64) from the encrypted response
            bit_65 = encrypted_response[127]
            # Map 0 to -1 and keep 1 as 1
            response = -1 if bit_65 == 0 else 1
            # Append the response
            responses.append(response)
            
        return np.array(responses)
