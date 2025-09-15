# SecureHashingAndEncryption

## Features
- SHA-256 hashing for text or files (`hash`)
- Caesar cipher encrypt/decrypt for text (`caesar`)
- RSA digital signature sign/verify using OpenSSL (`gen-keys`, `sign`, `verify`)

## Requirements
- Python 3.8+
- OpenSSL installed and on your PATH (for sign/verify)

## Install
Check versions:
`python3 --version`
`openssl version`

## Usage
- **Hash text**
`python hashAndEncrypt.py hash --text "hello world"`
- **Hash file**
`python handAndEncrypt.py hash --file ./example.txt`
- **Encrypt (Caesar)**
`python hashAndEncrypt.py caesar encrypt --text "hello world" --shift 3`
- **Decrypt (Caesar)**
`python hashAndEncrypt.py caesar decrypt --text "DwwdfnDwGdzq" --shift 3`

- **Generate RSA keys**
`python mini_crypto_app.py gen-keys --private private.pem --public public.pem`

- **Sign file**
`python mini_crypto_app.py sign --file ./example.txt --private private.pem --out example.sig`

- **Verify signature**
`python mini_crypto_app.py verify --file ./example.txt --public public.pem --sig example.sig`

## Notes
- SHA-256 uses Python’s `hashlib`.
- Caesar cipher shifts only A–Z/a–z; other characters pass through.
- Sign/verify shells out to OpenSSL: `dgst -sha256 -sign` and `dgst -sha256 -verify`
