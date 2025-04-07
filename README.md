<a id="readme-top"></a>

![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)

<br />
<div align="center">
  <h3 align="center">AndroCert</h3>

  <p align="center">
    Extract and display certificate information from APK files
    <br />
    <a href="https://github.com/rsenet/AndroCert"><strong>Explore the code »</strong></a>
  </p>
</div>

---

## What is AndroCert?

**AndroCert** is a Python tool designed to parse APK files and extract detailed information about the signing certificate(s), including:

- Hash fingerprints (SHA1, SHA256, MD5)
- Public key size and digest
- Issuer and subject info
- Validity period
- Inferred signature algorithm

Simple, effective, and built for mobile app pentesters or developers who want to verify APK signature details quickly.

---

## Usage

```bash
$ python3 androcert.py /path/to/file.apk

APK: universal.apk
Binary is signed: True
v1 signature: False
v2 signature: True
v3 signature: True
v4 signature: False
Algorithme de signature (inféré): SHA256withRSA
X.509 Subject: C=US,O=Android,CN=Android Debug
Signature Algorithm: rsassa_pkcs1v15
Valid From: 2022-09-09T19:23:49+00:00
Valid To: 2052-09-01T19:23:49+00:00
Issuer: C=US,O=Android,CN=Android Debug
Serial Number: 0x1
md5: 666c6af47d518b47ba557aaf5a9f4b56
sha1: de3d0b3929f72f47f4f9f5033396e9e92fadcea4
sha256: ce28b498601acd8b3a2df41b0f0e881e9e3f9cf23892e2ba02a70f8224d8b40a
sha512: 47f7cd785258eb6a15d24b3a14d0e6106d702dc5d5105d30bfd07a52ce4d78aa52bdd59dec73810b6baea1822b5b0c928287d04d87f8036cb745b4823eb15277
PublicKey Algorithm: rsa
Bit Size: 2048
Clé publique (DER, hex, début): 30820122300d06092a864886f70d01010105000382010f003082010a02820101...
Found certificates: 1
```

## Requirements

To use **AndroCert**, you need:

- Python ≥ 3.8
- [`pyaxmlparser`](https://github.com/dandro205/pyaxmlparser)
- [`cryptography`](https://pypi.org/project/cryptography/)

You can install dependencies with:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install pyaxmlparser cryptography
```

---

## Contributing

Contributions are welcome!  
If you find a bug or want to add a new feature, feel free to fork and submit a pull request.

Steps to contribute:

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a pull request

---

## Author

**Régis SENET**  
[https://github.com/rsenet](https://github.com/rsenet)

---

## License

This project is licensed under the [GPLv3 License](https://www.gnu.org/licenses/quick-guide-gplv3.en.html)
