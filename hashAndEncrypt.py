
#!/usr/bin/env python3
import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

# ---------- Hashing ----------
def sha256_string(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------- Caesar Cipher ----------
def caesar_shift(s: str, k: int, decrypt: bool = False) -> str:
    k = (-k) if decrypt else k
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)

# ---------- OpenSSL Helpers ----------
def require_openssl():
    try:
        subprocess.run(["openssl", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print("Error: OpenSSL is required but not found on PATH.", file=sys.stderr)
        sys.exit(1)

def gen_keys(private_path: str, public_path: str):
    require_openssl()
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", private_path, "-pkeyopt", "rsa_keygen_bits:2048"], check=True)
    subprocess.run(["openssl", "pkey", "-in", private_path, "-pubout", "-out", public_path], check=True)
    print(f"Generated:\n  Private: {private_path}\n  Public:  {public_path}")

def sign_file(file_path: str, private_key: str, signature_path: str):
    require_openssl()
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", private_key, "-out", signature_path, file_path], check=True)
    print(f"Signature written to {signature_path}")

def verify_file(file_path: str, public_key: str, signature_path: str) -> bool:
    require_openssl()
    res = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", public_key, "-signature", signature_path, file_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    print(res.stdout.strip())
    return "Verified OK" in res.stdout

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Mini crypto app: SHA-256, Caesar cipher, OpenSSL sign/verify.")
    sub = p.add_subparsers(dest="cmd", required=True)

    # hash
    ph = sub.add_parser("hash", help="SHA-256 of text or file")
    g = ph.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="Text to hash")
    g.add_argument("--file", help="Path to file to hash")

    # caesar
    pc = sub.add_parser("caesar", help="Caesar cipher encrypt/decrypt")
    pc.add_argument("mode", choices=["encrypt", "decrypt"])
    pc.add_argument("--text", required=True, help="Text to process")
    pc.add_argument("--shift", type=int, required=True, help="Shift amount (e.g., 3)")

    # gen-keys
    pk = sub.add_parser("gen-keys", help="Generate RSA keypair (OpenSSL)")
    pk.add_argument("--private", default="private.pem", help="Private key output path")
    pk.add_argument("--public", default="public.pem", help="Public key output path")

    # sign
    ps = sub.add_parser("sign", help="Sign a file (OpenSSL)")
    ps.add_argument("--file", required=True, help="File to sign")
    ps.add_argument("--private", default="private.pem", help="Private key PEM")
    ps.add_argument("--out", default=None, help="Signature output (default: <file>.sig)")

    # verify
    pv = sub.add_parser("verify", help="Verify a signature (OpenSSL)")
    pv.add_argument("--file", required=True, help="Signed file")
    pv.add_argument("--public", default="public.pem", help="Public key PEM")
    pv.add_argument("--sig", required=True, help="Signature file")

    args = p.parse_args()

    if args.cmd == "hash":
        if args.text is not None:
            print(sha256_string(args.text))
        else:
            print(sha256_file(args.file))

    elif args.cmd == "caesar":
        decrypt = args.mode == "decrypt"
        print(caesar_shift(args.text, args.shift, decrypt=decrypt))

    elif args.cmd == "gen-keys":
        gen_keys(args.private, args.public)

    elif args.cmd == "sign":
        sig = args.out or (args.file + ".sig")
        sign_file(args.file, args.private, sig)

    elif args.cmd == "verify":
        ok = verify_file(args.file, args.public, args.sig)
        sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
