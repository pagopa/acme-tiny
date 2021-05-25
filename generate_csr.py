import argparse, logging, os, textwrap, sys
import cryptography.hazmat.primitives.asymmetric.rsa

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def get_csr(common_name, out, keyout, rsa_key_size):

    log = LOGGER
    # generate private_key
    private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537, # this is RSA e exponent. DO NOT CHANGE!
        key_size = rsa_key_size
    )
    # save private_key
    with open(keyout, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
                format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=cryptography.hazmat.primitives.serialization.NoEncryption()
            )
        )
    log.info("Private key saved to %s", keyout)

    # build CSR
    builder = cryptography.x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(cryptography.x509.Name(
        [cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, common_name)] # set Common Name
    ))
    builder = builder.add_extension(cryptography.x509.BasicConstraints(ca=False, path_length=None), critical=True) # set Basic Const.
    builder = builder.add_extension(cryptography.x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), # set Extended Key Usage
        critical=True)
    builder = builder.add_extension(
            cryptography.x509.ExtendedKeyUsage([cryptography.x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), # set Extended Key Usage
        critical=False)
    csr = builder.sign(private_key, cryptography.hazmat.primitives.hashes.SHA256())
    # save CSR
    with open(out, "wb") as f:
        f.write(
            csr.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.DER)
        )
    log.info("CSR saved to %s", out)

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script generates a CSR in DER format, expecting the needed values in environment variables.

            Example Usage:
            python generate_csr.py --common-name example.com
            """)
    )
    parser.add_argument("--common-name", required=True, help="X509 Common Name string")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="Suppress output except for errors")
    parser.add_argument("--rsa-key-size", default=2048, type=int, choices=[2048, 3072, 4096], help="RSA key size in bits")
    parser.add_argument("--out", default="csr.der", help="Destination of the CSR")
    parser.add_argument("--keyout", default="csr.key", help="Destination of the CSR private key")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    # TODO add support for SAN field
    get_csr(args.common_name, args.out, args.keyout, args.rsa_key_size)

if __name__ == "__main__":
    main(sys.argv[1:])
