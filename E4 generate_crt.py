from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime, ipaddress

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Jammu & Kashmir"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Jammu"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mydomain.local"),
])

cert_builder = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.DNSName(u"mydomain.local"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
        ]),
        critical=False
    )
)

certificate = cert_builder.sign(private_key=private_key, algorithm=hashes.SHA256())

with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("certificate.pem", "wb") as f:
    f.write(certificate.public_bytes(serialization.Encoding.PEM))

print("Generated: private_key.pem, certificate.pem")
