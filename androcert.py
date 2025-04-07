import sys
import json
import argparse
from pyaxmlparser import APK
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

def infer_signature_algo(cert):
    public_key = cert.public_key()
    try:
        cert.fingerprint(hashes.SHA256())
        hash_algo = "SHA256"
    except Exception:
        hash_algo = "SHA1"

    if isinstance(public_key, rsa.RSAPublicKey):
        return f"{hash_algo}withRSA"
    elif isinstance(public_key, dsa.DSAPublicKey):
        return f"{hash_algo}withDSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"{hash_algo}withECDSA"
    return f"{hash_algo}withUnknownAlgo"

def analyze_apk(apk_path):
    apk = APK(apk_path)
    der_cert = apk.get_certificates_der_v2()[0]
    cert = x509.load_der_x509_certificate(der_cert, backend=default_backend())
    pubkey = cert.public_key()

    pubkey_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        key_size = pubkey.key_size
    except AttributeError:
        key_size = "Unknown"

    info = {
        "APK": apk_path,
        "Binary is signed": apk.is_signed(),
        "v1 signature": apk.is_signed_v1(),
        "v2 signature": apk.is_signed_v2(),
        "v3 signature": apk.is_signed_v3(),
        "v4 signature": False,
        "Algorithme de signature (inféré)": infer_signature_algo(cert),
        "X.509 Subject": cert.subject.rfc4514_string(),
        "Signature Algorithm": "rsassa_pkcs1v15",
        "Valid From": cert.not_valid_before_utc.isoformat(),
        "Valid To": cert.not_valid_after_utc.isoformat(),
        "Issuer": cert.issuer.rfc4514_string(),
        "Serial Number": hex(cert.serial_number),
        "md5": cert.fingerprint(hashes.MD5()).hex(),
        "sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "sha512": cert.fingerprint(hashes.SHA512()).hex(),
        "PublicKey Algorithm": type(pubkey).__name__.replace("PublicKey", "").lower(),
        "Bit Size": key_size,
        "Clé publique (DER, hex, début)": pubkey_bytes.hex()[:64] + "...",
        "Found certificates": 1,
    }

    return info

def main():
    parser = argparse.ArgumentParser(description="APK certificate inspection tool")
    parser.add_argument("apk", help="APK file to inspect")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    args = parser.parse_args()

    info = analyze_apk(args.apk)

    if args.json:
        print(json.dumps(info, indent=4))
    else:
        for key, value in info.items():
            print(f"{key}: {value}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python3 androcert.py <fichier.apk> [--json]")
        sys.exit(1)
    main()
