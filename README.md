
# QuantumShield - Quantum-Resistant Encryption Tool

QuantumShield is a GUI-based application designed for encrypting and decrypting files using quantum-resistant cryptography.

## Features

- **Quantum-Resistant Cryptography**: Utilizes the Kyber512 algorithm.
- **Secure File Encryption and Decryption**.
- **User-Friendly GUI** built with Tkinter.
- **Key Management**: Public and private key pair generation.

## Prerequisites

- Python 3.8 or above.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/QuantumShield.git
   cd QuantumShield
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python QuantumShield_v2.py
   ```

2. Use the GUI to:
   - Select input files.
   - Generate public/private keys.
   - Encrypt and decrypt files.

## File Structure

```
QuantumShield/
├── QuantumShield_v2.py      # Main application file
├── requirements.txt         # Python dependencies
├── public_key.key           # Public key (generated at runtime)
├── private_key.key          # Private key (generated at runtime)
├── key_ciphertext.bin       # Encrypted key data (runtime)
├── README.md                # Project documentation
```

## Contributions

Feel free to submit pull requests or report issues to improve QuantumShield.

## License

[MIT License](LICENSE)

## Author

Xeloria
