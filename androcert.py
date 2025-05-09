import sys
import os
import csv
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
    certs_v2 = apk.get_certificates_der_v2()

    if not certs_v2:
        raise ValueError("Aucun certificat v2 trouvé (liste vide)")

    der_cert = certs_v2[0]
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

    return {
        "APK": apk_path,
        "Binary is signed": apk.is_signed(),
        "v1 signature": apk.is_signed_v1(),
        "v2 signature": apk.is_signed_v2(),
        "v3 signature": apk.is_signed_v3(),
        "v4 signature": False,
        "Algorithme de signature (inféré)": infer_signature_algo(cert),
        "X.509 Subject": cert.subject.rfc4514_string(),
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
    }


def main():
    parser = argparse.ArgumentParser(description="APK certificate inspection tool")
    parser.add_argument("apk", help="APK file or directory to inspect")
    parser.add_argument("--csv", action="store_true", help="Écrire les résultats dans un fichier CSV")
    args = parser.parse_args()

    if os.path.isdir(args.apk):
        apk_files = []
        for root, _, files in os.walk(args.apk):
            for fname in files:
                if fname.lower().endswith('.apk'):
                    apk_files.append(os.path.join(root, fname))

        if not apk_files:
            print(f"Aucun fichier .apk trouvé dans le répertoire : {args.apk}")
            sys.exit(1)
    else:
        apk_files = [args.apk]

    results = []

    for apk_path in apk_files:
        try:
            info = analyze_apk(apk_path)
        except Exception as e:
            try:
                apk = APK(apk_path)
                context_info = {
                    "APK": apk_path,
                    "Binary is signed": apk.is_signed(),
                    "v1 signature": apk.is_signed_v1(),
                    "v2 signature": apk.is_signed_v2(),
                    "v3 signature": apk.is_signed_v3(),
                    "v4 signature": False,  # non supporté par pyaxmlparser
                    "Error": str(e)
                }
            except Exception as e2:
                context_info = {
                    "APK": apk_path,
                    "Error": f"{e} (échec extraction signature: {e2})"
                }
            results.append(context_info)
            print(f"Erreur lors de l'analyse de {apk_path}: {e}")

        else:
            results.append(info)

    if args.csv:
        if not results:
            print("Aucun résultat à écrire.")
            sys.exit(1)

        first = results[0]
        fieldnames = list(first.keys())

        if any("Error" in r for r in results) and "Error" not in fieldnames:
            fieldnames.append("Error")

        base = os.path.basename(os.path.normpath(args.apk))
        output_file = f"{base}.csv"

        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)

        print(f"Résultats CSV écrits dans : {output_file}")

    else:
        for info in results:
            print("----------------------------------------")

            for k, v in info.items():
                print(f"{k}: {v}")
        print("----------------------------------------")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python3 androcert.py <fichier.apk|répertoire> [--csv]")
        sys.exit(1)

    main()
