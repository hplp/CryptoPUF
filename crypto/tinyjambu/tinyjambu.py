import ctypes
import os

# Get the directory of the current script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the path to the shared library
lib_path = os.path.join(current_dir, 'libtinyjambu.so')

# Load the shared library
lib = ctypes.CDLL(lib_path)  # On Linux or macOS
# lib = ctypes.CDLL('tinyjambu.dll')    # On Windows

# Define function prototypes for encryption and decryption
lib.crypto_aead_encrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte),  # ciphertext output
                                    ctypes.POINTER(ctypes.c_ulonglong),  # ciphertext length output
                                    ctypes.POINTER(ctypes.c_ubyte),  # message input
                                    ctypes.c_ulonglong,  # message length
                                    ctypes.POINTER(ctypes.c_ubyte),  # associated data input
                                    ctypes.c_ulonglong,  # associated data length
                                    ctypes.POINTER(ctypes.c_ubyte),  # nsec
                                    ctypes.POINTER(ctypes.c_ubyte),  # nonce input
                                    ctypes.POINTER(ctypes.c_ubyte)]  # key input

lib.crypto_aead_decrypt.argtypes = [ctypes.POINTER(ctypes.c_ubyte),  # plaintext output
                                    ctypes.POINTER(ctypes.c_ulonglong),  # plaintext length output
                                    ctypes.POINTER(ctypes.c_ubyte),  # nsec
                                    ctypes.POINTER(ctypes.c_ubyte),  # ciphertext input
                                    ctypes.c_ulonglong,  # ciphertext length
                                    ctypes.POINTER(ctypes.c_ubyte),  # associated data input
                                    ctypes.c_ulonglong,  # associated data length
                                    ctypes.POINTER(ctypes.c_ubyte),  # nonce input
                                    ctypes.POINTER(ctypes.c_ubyte)]  # key input


class SimpleTinyJAMBU:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce

    def encrypt(self, plaintext):
        # Encrypt using TinyJAMBU
        ciphertext = encrypt(plaintext, self.key, self.nonce)
        return ciphertext
    
def hex_to_byte_array(hex_str):
    return (ctypes.c_ubyte * (len(hex_str) // 2))(*[int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)])

def encrypt(plaintext, key_hex, nonce_hex):
    key = hex_to_byte_array(key_hex)
    nonce = hex_to_byte_array(nonce_hex)

    ciphertext = (ctypes.c_ubyte * 64)()
    ciphertext_len = ctypes.c_ulonglong()

    # Prepare plaintext as bytes
    plaintext_bytes = (ctypes.c_ubyte * len(plaintext))(*plaintext)

    lib.crypto_aead_encrypt(ciphertext, ctypes.byref(ciphertext_len),
                            plaintext_bytes, len(plaintext), None, 0, None, nonce, key)

    # Return ciphertext as a raw byte string instead of hex
    return bytes(ciphertext[:ciphertext_len.value])

def decrypt(ciphertext_bytes, key_hex, nonce_hex):
    ciphertext = (ctypes.c_ubyte * len(ciphertext_bytes))(*ciphertext_bytes)
    key = hex_to_byte_array(key_hex)
    nonce = hex_to_byte_array(nonce_hex)

    plaintext = (ctypes.c_ubyte * 64)()
    plaintext_len = ctypes.c_ulonglong()

    ret = lib.crypto_aead_decrypt(plaintext, ctypes.byref(plaintext_len), None,
                                  ciphertext, len(ciphertext_bytes), None, 0, nonce, key)
    
    if ret == 0:
        return bytes(plaintext[:plaintext_len.value])
    else:
        return "Decryption failed"
