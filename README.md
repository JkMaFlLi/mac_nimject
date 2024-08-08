# MAC Address Shellcode Execution with XOR Encryption

This project demonstrates how to encrypt shellcode using XOR, format it as MAC addresses for obfuscation, and then decrypt and execute it in a Windows environment using Nim.

## Overview

The process involves two main steps:

1. **Encryption**: A Python script reads a binary shellcode file, encrypts it using XOR, and formats the encrypted data as MAC addresses.
2. **Decryption and Execution**: A Nim script reads the encrypted MAC addresses, decrypts the data using XOR, and executes the shellcode using Windows fibers.

## Files

- **encrypt_shellcode.py**: The Python script that encrypts shellcode and outputs it in MAC address format.
- **macinject2.nim**: The Nim script that decrypts the MAC address formatted shellcode and executes it.

## Requirements

### Python
- Python 3.x
- `encrypt_shellcode.py` does not require any external libraries.

### Nim
- Nim 1.x or higher
- The `winim` Nim package for Windows API functions.

## Usage

### Step 1: Encrypt Shellcode

First, use the Python script to encrypt your shellcode and format it as MAC addresses.

```bash
python encrypt_shellcode.py shellcode.bin
```
Replace shellcode.bin with the path to your binary shellcode file. The script will output the encrypted shellcode in MAC address format.

### Step 2: Update the Nim Script
Copy the output from the Python script and replace the encryptedMAC array in macinject2.nim with the generated MAC addresses.

### Step 3: Compile and Run the Nim Script
Finally, compile and run the Nim script to execute the decrypted shellcode.

```bash
nim c -r macinject2.nim
```
## Running the Nim Script
Compile and run the Nim script:

```bash
nim c -r macinject2.nim
```
## Notes
Ensure that the XOR key used in both the Python and Nim scripts is the same.
The project is intended for educational purposes and should be used responsibly.

