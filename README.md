# Overview
encrypt is a small utility which was initially created for shellcode protection, but has since been adapted to protect arbitrary strings. encrypt can take one or more comma-separated strings, or any raw position independent shellcode and encrypt it. Encryption takes place using AES-256 with a user-supplied or randomly generated alphanumeric key, salt and/or initialization value. encrypt then outputs a decryption routine in either C# or C++ to file or CLI, depending on what is selected.

## Why?
encrypt was inspired after taking the [Sektor7 RTO Malware Development Essentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials) course, which I cannot recommend enough. Shellcode aside, encrypting strings can be quite useful when you are hiding certain function calls from the IAT (function call obfuscation). This is a well-known practice when evading endpoint security. For example, if you want to call `QueueUserApc`, you will need to bring in the function prototype and create a pointer like `pQueueUserApc = GetProcAddress(GetModuleHandle("kernel32.dll"),"QueueUserApc");`. While this will remove `QueueUserApc` from the IAT, scanning engines can still do the equivilent of `strings` and find that `QueueUserApc` is in the compiled PE as it is a cleartext string. That’s the long way around for saying - if you need to call function names, you should probably encrypt them.

# Usage
You can grab a copy of encrypt from the [releases](https://github.com/skahwah/encrypt/releases/) page. Alternatively, feel free to compile the solution yourself. encrypt relies on the `templates` folder being in the same directory as `encrypt.exe` (a check is done at runtime). This has also been made available on the releases page.

The following input types are supported:
- **File:** A raw/binary position independent shellcode file, such as a Cobalt Strike `beacon.bin`. This can be supplied either by it's current, relative, or full path.
- **String:** One or more arbitrary strings that are comma-separated.

```
encrypt.exe -h
encrypt.exe

Examples:
        encrypt.exe -l cs -m file -i C:\test\beacon.bin -e random -o file
        encrypt.exe -l cpp -m string -i VirtualAlloc,LoadLibrary -e manual -k oC95@#Qy -s 2cVMpO!0 -v cf8U4v%M -o cli

Language (-l):
        -l cpp - Create C/C++ encrypted output
        -l cs - Create C# encrypted output

Mode (-m):
        -m file -a FILE- Read in a raw/binary position independent shellcode file
        -m string -a - Read in one or more comma-seperated strings

Input (-i):
        -i C:\test\beacon.bin
        -i VirtualAlloc,LoadLibrary

Encryption Type (-e):
        -e random - Randomly generate a alphanyumeric key, salt and initialization value
        -e manual - Manually supply a alphanumeric key, salt and initialization value. This requires the following three arguments:
                 -k Password123
                 -s Salt123
                 -i InitVal123

Ouput (-o):
        -o cli - Ouput to CLI
        -o file - Output to template files
```
## Usage: C# File Mode with Randomly Encryption Material Output to File
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe -l cs -m file -i ..\beacon.bin -e random -o file

[+] File encryption mode
[+] Lang: cs
[+] Key: oVGhPyvOt5nqHS0BO
[+] Salt: 7PmbgoaTkm7xaTRI2a26W60TY5ViCDeynbSTZnOsg7njS74EJ910KT

[+] Encrypted raw shellcode file created: c:\users\skawa\desktop\beacon-encrypted.bin
[+] C# Template file created: c:\users\skawa\desktop\beacon-encrypted.cs
```

## Usage: C# String Mode with User-Supplied Encryption Material Output to CLI
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe -l cs -m string -i VirtualAlloc,LoadLibrary,VirtualProtect -e manual -k oC9asdf1355@#Qy -s 2cjnsq91O!0 -v cf13rsacf8U4v%M -o cli

[+] String encryption mode
[+] Lang: cs
[+] Key: oC9asdf1355@#Qy
[+] Salt: 2cjnsq91O!0

[+] Encrypted: VirtualAlloc
[+] Encrypted: LoadLibrary
[+] Encrypted: VirtualProtect

byte[] passwordBytes = new byte[] { 67, 108, 214, 254, 105, 35, 107, 133, 77, 5, 45, 127, 6, 127, 175, 83, 169, 118, 22, 211, 231, 185, 154, 234, 134, 249, 144, 245, 88, 80, 134, 136, };

byte[] saltBytes = new byte[] { 229, 127, 26, 1, 72, 167, 247, 214, 33, 29, 139, 124, 103, 135, 85, 147, 118, 247, 164, 76, 23, 211, 226, 162, 22, 0, 221, 197, 18, 55, 24, 14, };

byte[] virtualalloc_enc = new byte[] { 134, 181, 237, 72, 90, 40, 88, 20, 153, 216, 147, 165, 233, 7, 122, 203, };
byte[] virtualalloc = DecryptShellcode(passwordBytes, saltBytes, virtualalloc_enc);

byte[] loadlibrary_enc = new byte[] { 151, 119, 31, 92, 130, 163, 141, 163, 96, 31, 178, 234, 114, 253, 124, 254, };
byte[] loadlibrary = DecryptShellcode(passwordBytes, saltBytes, loadlibrary_enc);

byte[] virtualprotect_enc = new byte[] { 118, 164, 103, 91, 48, 237, 160, 217, 245, 31, 90, 245, 237, 101, 6, 244, };
byte[] virtualprotect = DecryptShellcode(passwordBytes, saltBytes, virtualprotect_enc);
```

## Usage: C/C++ File Mode with User-Supplied Encryption Material Output to File
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe -l cpp -m file -i c:\users\skawa\desktop\beacon.bin -e manual -k Password1 -s Salt2 -v IV123! -o file

[+] File encryption mode
[+] Lang: cpp
[+] IV: IV123!
[+] Key: Password1

[+] Encrypted raw shellcode file created: c:\users\skawa\desktop\beacon-encrypted.bin
[+] C++ Template file created: c:\users\skawa\desktop\beacon-encrypted.cpp
```

## Usage: C/C++ String Mode with Random Encryption Material Output to CLI
```
C:\Users\skawa\Desktop\encrypt>encrypt.exe -l cpp -m string -i VirtualAlloc -e random -o cli

[+] String encryption mode
[+] Lang: cpp
[+] IV: f2jb5VuUQ0GWJdbg1ARASsovBOHGyKhdqZR90bPKMrB2MtwMEVRH1tlWMXK
[+] Key: cnkwrWWMeuub65q4oFxgC9LiNE7NJE9x0YdhXs12p5ad

[+] Encrypted: VirtualAlloc

char iv[] = { 0xD5, 0xBE, 0x34, 0x9D, 0x10, 0x5D, 0x03, 0x1A, 0x00, 0x67, 0x45, 0x24, 0x6A, 0x9D, 0xB6, 0xCD };

char key[] = { 0x63, 0x6E, 0x6B, 0x77, 0x72, 0x57, 0x57, 0x4D, 0x65, 0x75, 0x75, 0x62, 0x36, 0x35, 0x71, 0x34, 0x6F, 0x46, 0x78, 0x67, 0x43, 0x39, 0x4C, 0x69, 0x4E, 0x45, 0x37, 0x4E, 0x4A, 0x45, 0x39, 0x78, 0x30, 0x59, 0x64, 0x68, 0x58, 0x73, 0x31, 0x32, 0x70, 0x35, 0x61, 0x64 };

unsigned char VirtualAlloc[] = { 0x5D, 0x95, 0x80, 0xFC, 0x2B, 0x01, 0x2F, 0x0C, 0x34, 0xC5, 0xD2, 0x85, 0x0E, 0x5C, 0x79, 0xB8 };
unsigned int VirtualAlloc_len = sizeof(VirtualAlloc);
```

If you look at the first line of the output file, you will find the necessary commands to compile the payload. In cases where the output option is set to `file`, the template file will have a vanilla injection routine which is designed just to test if the decryption routine (which is what you really want) works. If the output option is set to `cli`, the decryption routine will not be printed to screen (to save space). This can be pulled from the corresponding templates file in the `templates` directory.

# Credits
- [Sektor7 RTO Malware Development Essentials](https://institute.sektor7.net/red-team-operator-malware-development-essentials) course.
