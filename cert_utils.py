from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, CertificateBuilder, random_serial_number
from cryptography import x509
import datetime


def generate_ca_cert(country_code_ca, province_ca, locality_ca, organization_ca, common_name_ca):
    """ Generate a self-signed CA certificate and return it as a downloadable file """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code_ca),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province_ca),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_ca),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_ca),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name_ca),
    ])

    ca_cert = (

        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    return ca_key_pem, ca_cert_pem


def generate_partner_cert(country_code_part, province_part, locality_part, org_name_part, common_name_part, ca_key_pem, ca_cert_pem):
    """ Generate a Partner certificate signed by CA and return it as a downloadable file """
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    partner_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, country_code_part),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province_part),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality_part),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name_part),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name_part),
            ])
        )
        .sign(partner_key, hashes.SHA256())
    )

    partner_cert = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .sign(ca_key, hashes.SHA256())
    )

    partner_key_pem = partner_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    partner_cert_pem = partner_cert.public_bytes(serialization.Encoding.PEM)

    return partner_key_pem, partner_cert_pem
