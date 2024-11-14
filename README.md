# CryptoPUF: A Lightweight and ML-Resilient Strong PUF Based on a Weak PUF and Crypto Core

CryptoPUF is a lightweight, machine-learning-resilient Physically Unclonable Function (PUF) implementation designed for secure, efficient authentication/encryption. By combining a weak PUF (DD-PUF) with a cryptographic encryption core (TinyJAMBU), CryptoPUF provides improved resistance against machine learning attacks and is optimized for low-power IoT and edge devices.

## Features
- **Lightweight Design**: Combines a weak PUF (e.g. DD-PUF) with a crypto core (e.g. TinyJAMBU) to offer security in hardware-constrained environments.
- **Machine Learning Resilience**: Integrates a cryptographic core to reduce vulnerability to ML-based attacks.
- **Configurable Challenge-Response Pairs (CRPs)**: Supports customizable CRP generation and testing.
- **Extensibility**: Allows users to support new cryptographic algorithms by adding a subfolder under  [crypto](https://github.com/YiminGao0113/CryptoPUF/blob/main/crypto) with the defined encryption function. (TinyJAMBU can be used as a template example).

## Installation

### Prerequisites
- Python 3.7+
- Required packages: `numpy`, `scikit-learn`, `matplotlib`

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/CryptoPUF_repo.git
   cd CryptoPUF_repo
2. **Run the example Jupyter notebooks**

   Explore the included notebooks to see how to model a CryptoPUF and evaluate its resilience to various ML attacks.
   
4. **Extensible Cryptographic Core**

The CryptoPUF implementation is designed to allow easy integration of different cryptographic cores. The `crypto_functions` dictionary in [crypto/cryptopuf.py](https://github.com/YiminGao0113/CryptoPUF/blob/main/crypto/cryptopuf.py) maps each crypto core name to its corresponding encryption function, enabling you to add and configure new cryptographic algorithms simply by updating this dictionary. By default, it supports TinyJAMBU, but other cryptographic functions can be added as needed.


5. **Paper Results**
    The full results for the CryptoPUF paper are available at [CryptoPUF Results Repository](https://github.com/YiminGao0113/CryptoPUF_results).
