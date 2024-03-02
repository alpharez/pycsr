# pyCSR2

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import yaml

if __name__ == '__main__':
    with open("csr.yaml") as file:
        try:
            csr = yaml.safe_load(file)
            san_names = []
            for san in csr['sans']:
                san_names.append(x509.DNSName(san['name']))
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, csr['country']),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, csr['state']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, csr['locality']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, csr['organization']),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, csr['organizational_unit']),
                x509.NameAttribute(NameOID.COMMON_NAME, csr['common_name']),
            ])).add_extension(
                 x509.SubjectAlternativeName(san_names),
                 critical=False,
            ).sign(key, hashes.SHA256())
            print(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()).decode())
            print(csr.public_bytes(serialization.Encoding.PEM).decode())
        except yaml.YAMLError as exc:
            print(exc)