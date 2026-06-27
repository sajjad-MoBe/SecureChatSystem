# Secure Chat System

This project is a small educational secure messaging system built for a Data and Network Security course.
It demonstrates the main building blocks used in a protected message exchange flow:

- RSA key generation, encryption, decryption, signing, and verification
- A simple Public Key Infrastructure (PKI) with a Certificate Authority (CA)
- Authenticated Diffie-Hellman key exchange
- A custom Feistel-based symmetric cipher for message encryption and decryption

The program is written in Python and is intended for learning and demonstration purposes.
It should not be used as a real-world cryptographic implementation.

## Project Structure

```text
.
├── main.py
├── src/
│   ├── phase1.py
│   ├── phase2.py
│   └── phase3.py
└── tests/
    ├── _bootstrap.py
    ├── test_phase1.py
    ├── test_phase2.py
    └── test_phase3.py
```

## Requirements

- Python 3.10 or newer
- No external Python packages are required

## Running the Main Program

Run the interactive secure cryptography system from the project root:

```bash
python3 main.py
```

The menu allows you to:

1. Initialize the system and generate keys/certificates
2. Establish a shared key using authenticated Diffie-Hellman
3. Encrypt a message
4. Decrypt a message
5. Show the current system status
6. Exit

## Running Tests

Run all tests from the project root:

```bash
python3 -m unittest discover -s tests
```

You can also run the tests from inside the `tests` directory:

```bash
cd tests
python3 -m unittest discover
```

Run a single test file:

```bash
python3 -m unittest tests/test_phase1.py
python3 -m unittest tests/test_phase2.py
python3 -m unittest tests/test_phase3.py
```

## Project Report

The Persian project report is available in [report_Fa.md](./report_Fa.md).

## Contributors
- Sajjad Mohammadbeigi
- Aida Ameri
