# umbrella
> Protect your shellcode from the rain.

---
![rain](assets/rain.jpg)
## Description

Umbrella is a robust shellcode encryptor/obfuscator/encoder built to strengthen the security and stealth of your payloads. It's specifically developed to streamline malware development and red-team operations.

This tool is vibe-coded, so it might contain some bugs expect occasional hiccups and feel free to report any issues you encounter.

## ☕ Support

If you find this project useful, consider buying me a coffee:

- [![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-yellow?logo=buy-me-a-coffee&style=flat-square)](https://www.buymeacoffee.com/pipapupatuta)

- BTC: bc1qdd5uvhlsd8g056lz5mx288snlxq9z4fk42jj8r
## Features

- **Encryption Algorithms:**  
  AES, RC4, XOR, Salsa20, ChaCha20, Caesar, RSA

- **Obfuscation Techniques:**  
  IPv4, IPv6, MAC, UUID, Reverse, Shikata Ga Nai  

- **Key Guard:**  
  Generates a “protected” version of your key plus a tiny brute-force stub (in C, Python, Rust, etc.) so that the real key never appears plainly in memory.  

- **Entropy Reduction:**  
  Options (compression + encoding) to lower the raw byte‐entropy of your shellcode—making it less likely to trigger high-entropy detections (e.g. gzip/zlib compression followed by Base85 or Base32).  

- **Encoding Options:**  
  Base16, Base32, Base64, Base85  

- **Compression:**  
  gzip, zlib, bz2, lzma  

- **Ready-to-Use Stubs:**  
  Automatically generate language-specific deobfuscation templates (C, C#, Python, Rust, Nim, Go, Perl, Ruby, PowerShell, VBA) so you can paste, compile, and recover the original bytes with no extra work.  

- **Output Formats for shellcode and key:**  
  C, C#, Python, Rust, Nim, Java, PowerShell, VBA, Perl, Ruby, Go, Raw  

- **Output Flexibility:**  
  Save to file or print directly to stdout 

## Installation

```bash
git clone https://github.com/yourusername/Umbrella.git
cd Umbrella
pip install -r requirements.txt
python3 umbrella.py
```

## Usage
```

        ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀|⣀⣀⣀⠀⠀⣤⡀⠀⠀⠀|⠀⠀⠀⠀         |
    |   ⠀|⠀⢀⡠⠔⠂⠉⠁⠀⠀⠀⡀⠤⠒⠉⠙⠲⢇⡀⠀⠀⠀⠀⠀⠀⠀
        ⢀⣠⣖⣁⣀⣀⣀⡀⠀⢀⠠⠈⠀⠀⠀⠀⠀⠀⠀⢹⠦⡀⠀⠀|⠀⠀
    |   ⠻⢯⡀⠀⢀⡠⠂⠉⠑⠣⠤⢄⣀⠀⠀⠀⠀⠀⠀⠈⡀⠈⢆⠀⠀⠀⠀
|       ⠀⠀⠙⠶⢀⡀⠀⠀⠀⠀⢀⠔⠁⠉⠖⡦⣄⠀⠀⠀⡇⠀⠀⠳⡀⠀⠀ |
        ⠀⠀⠀⠀⠀⠈⠑⢦⠀⡰⠁⠀⠀⡜⡜⠀⢀⠛⢦⡀⠇⠀⠀⠀⠱⠀⠀
    |   ⠀⠀|⠀⠀⠀⠀⠀⠙⠒⠢⠤⣸⡸⠁⠀⡌⠀⠀⠹⠤⣀⠀⠀⠀⢣⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀|⠀⠀⠰⠱⠑⢆⡐⠀⠀⠀⠀⠀⠀⡗⢦⠀⠈⡄
        ⠀⠀⠀|⠀⠀⠀⠀⠀⠀⢠⢣⠃⠀⠀⠉⠉⠉⠒⠤⡀⢰⠀⠀⢣⠀⡇
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢃⠇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠀⠀⠒⡷⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠎⠎⠀⠀|⠀⠀⠀⠀⠀⠀|⠀⠀⠀⠀⠀⠀
|       ⠀⠀⠀|⠀⠀⠀⢀⣜⡜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀          |
        ⠀⠀⣠⢤⠀⠀⢀⡎⢻⠂⠀⠀⠀⠀⠀⠀|⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⡇⢸⡀⠀⡜⢀⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ |
        ⠀⠀⠙⠤⣉⢉⡠⠎⠀⠀⠀⠀|⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀|⠀⠀⠀
    |
                𝚄𝚖𝚋𝚛𝚎𝚕𝚕𝚊
usage: super_encryptor.py [-h] [-i FILE] [-o OUTPUT] (-enc {aes,rc4,xor,salsa20,chacha20,caesar,polymorphic,rsa,shikata_ga_nai} | -obf {ipv4,ipv6,mac,uuid,reverse} | --key-guard) [-key KEY(hex)] [-key-len int] [-var variable_name]
                          [-format {raw,c,csharp,python,rust,nim,java,powershell,vba,perl,ruby,go}] [-format-key {raw,c,csharp,python,rust,nim,java,powershell,vba,perl,ruby,go}] [-stub-format {c,csharp,python,rust,nim,java,powershell,vba}]
                          [-entropy [{base32,base64,base16,base85}]] [-compress {zlib,gzip,bz2,lzma}] [-sub SUB] [-rounds ROUNDS] [-stdout]

Umrella that will protect your shellcode from rain.

options:
  -h, --help            show this help message and exit
  -i, --input FILE
  -o, --output OUTPUT
  -enc, --encrypt {aes,rc4,xor,salsa20,chacha20,caesar,polymorphic,rsa,shikata_ga_nai}
  -obf, --obfuscate {ipv4,ipv6,mac,uuid,reverse}
  --key-guard           Generate ProtectedKey + brute-forcer (no shellcode)
  -key KEY(hex)
  -key-len int
  -var variable_name
  -format, --format-shellcode {raw,c,csharp,python,rust,nim,java,powershell,vba,perl,ruby,go}
  -format-key {raw,c,csharp,python,rust,nim,java,powershell,vba,perl,ruby,go}
  -stub-format {c,csharp,python,rust,nim,java,powershell,vba}
                        Language of brute-force stub only when using --key-guard
  -entropy [{base32,base64,base16,base85}]
                        Apply Base-N encoding to final shellcode (default: base32)
  -compress {zlib,gzip,bz2,lzma}
                        Compress processed data (zlib/gzip/bz2/lzma)
  -sub SUB              Public key file (PEM for RSA / ASCII armor PGP)
  -rounds ROUNDS        Number of Shikata‐Ga‐Nai iterations (only used if -enc shikata_ga_nai)
  -stdout               Print final result to STDOUT (instead of writing to a file)
```

## Usage Examples
- AES Encryption (output shellcode and key in C format):
```bash
python umbrella.py -enc aes -key-len 32 -i payload.bin -o encrypted_payload.c -format c -format-key c
```
- IPv4 Obfuscation (output in C):
```bash
python umbrella.py -obf ipv4 -i payload.bin -o ipv4_shellcode.c -format c
```
- Key Guard:
```bash
python umbrella.py --key-guard -key a76067532ae68146725dc92177172aea -format c -format-key c
```
Compress & Base85 Encode:
```bash
python umbrella.py -enc rc4 -key a76067532ae68146725dc92177172aea -key-len 16 -compress -entropy base85 -i payload.bin -o payload.txt -format c -format-key c
```
- Output to stdout:
```bash
python umbrella.py -enc aes -format-key c -format python -i payload.bin -stdout
```
## References

- [MalDev Academy](https://maldevacademy.com/)

## Disclaimer

Umbrella is intended for educational purposes and authorized penetration testing only. Use responsibly.
