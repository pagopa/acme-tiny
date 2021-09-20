#!/usr/bin/env python3

import argparse
import datetime
import logging
import textwrap
import sys
import cryptography.x509


LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


def check_timedelta(certificate, delta):

    log = LOGGER

    # parse the certificate
    log.info("Parsing the --certificate file...")
    with open(certificate, "rb") as f:
        cert_raw = f.read()
    cert = cryptography.x509.load_pem_x509_certificate(cert_raw)

    # read the expiring time
    nva = cert.not_valid_after
    log.info("The certificate is not valid after %s", str(nva))

    # is the cert expiring before the time delta?
    expired = (datetime.datetime.now() + datetime.timedelta(seconds=delta) > nva)
    if expired:
        log.info(
            "The certificate is expiring before the chosen time delta (%ss)", delta)
        # return a 1 status code so that shells can interpret the result
        sys.exit(1)
    else:
        log.info(
            "The certificate is not expiring before the chosen time delta (%ss)", delta)
        # all good
        sys.exit(0)


def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script checks that a certificate is expiring later than a specified delta.
            Status code is 1 in case of exception or an expiring certificate.

            Example Usage:
            python3 check_certificate_expiry.py --certificate certificate.pem --delta 3600
            """)
    )
    parser.add_argument("--certificate", required=True,
                        help="Path to the x509 certificate to check")
    parser.add_argument("--delta", default=720, type=int,
                        help="Positive time delta in seconds (3600 -> 1h)")
    parser.add_argument("--quiet", action="store_const",
                        const=logging.ERROR, help="Suppress output except for errors")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    check_timedelta(args.certificate, args.delta)


if __name__ == "__main__":
    main(sys.argv[1:])
