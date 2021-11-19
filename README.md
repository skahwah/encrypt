# Overview
encrypt is a small utility which was initially created for shellcode protection, but has since been adapted to protect arbitrary strings. encrypt can take one or more comma-separated strings, or any raw position independent shellcode and encrypt it using AES-256 with a randomly generated alphanumeric key, salt and/or initialization value. encrypt then outputs a decryption routine in either C# or C++.

## Why?
encrypt was inspired after taking the [Sektor7 RTO Malware Development Essentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials) course, which I cannot recommend enough. Shellcode aside, encrypting strings can be quite useful when you are hiding certain function calls from the IAT (function call obfuscation). This is a well-known practice when evading endpoint security. For example, if you want to call `QueueUserApc`, you will need to bring in the function prototype and create a pointer like `pQueueUserApc = GetProcAddress(GetModuleHandle("kernel32.dll"),"QueueUserApc");`. While this will remove `QueueUserApc` from the IAT, scanning engines can still do the equivilent of `strings` and find that `QueueUserApc` is in the compiled PE as it is a cleartext string. That’s the long way around for saying - if you need to call function names, you should probably encrypt them.

# Usage
You can grab a copy of encrypt from the [releases](https://github.com/skahwah/encrypt/releases/) page. Alternatively, feel free to compile the solution yourself. encrypt relies on the `templates` folder being in the same directory as `encrypt.exe`. This has also been made available on the releases page.

The following input types are supported:
- **File:** A raw/binary position independent shellcode file, such as a Cobalt Strike `beacon.bin`. This can be supplied either by it's current, relative, or full path.
- **String:** One or more arbitrary strings that are comma-separated.

The input type is automatically detected. `encrypt.exe` will then output a decryption routine in either C# or C++ compatible formats depending on what is selected.

```
encrypt.exe

[!] encrypt.exe <mode: cs | cpp> <input: file | string>
```

## Usage: C# File Mode
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe cs ..\beacon.bin

[+] File encryption mode.

[+] Encrypted raw shellcode file created: C:\Users\skawa\Desktop\beacon-encrypted.bin
[+] C# Template file created: C:\Users\skawa\Desktop\beacon-encrypted.cs
```

## Usage: C# String Mode
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe cs QueueUserApc,VirtualProtect

[+] String encryption mode.

[+] Encrypted: QueueUserApc
[+] Encrypted: VirtualProtect

[+] C# Template file created: C:\Users\skawa\Desktop\encrypt\QueueUserApc-strings-encrypted.cs
```

## Usage: C++ File Mode
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe cpp C:\Users\skawa\Desktop\beacon.bin

[+] File encryption mode.

[+] Encrypted raw shellcode file created: C:\Users\skawa\Desktop\beacon-encrypted.bin
[+] C++ Template file created: C:\Users\skawa\Desktop\beacon-encrypted.cpp
```

## Usage: C++ String Mode
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe cpp VirtualAllocEx

[+] String encryption mode.

[+] Encrypted: VirtualAllocEx

[+] C++ Template file created: C:\Users\skawa\Desktop\encrypt\VirtualAllocEx-strings-encrypted.cpp
```

If you look at the first line of the output file, you will find the necessary commands to compile the payload. In the cases where shellcode encryption is selected, the template file will have a vanilla injection routine which is designed just to test if the decryption routine (which is what you really want) works.

# Credits
- [Sektor7 RTO Malware Development Essentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials) course.
