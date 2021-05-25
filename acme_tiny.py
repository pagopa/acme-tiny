#!/usr/bin/env python
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import argparse, base64, hashlib, json, logging, os, re, sys, textwrap, time
from urllib.request import urlopen, Request
import cryptography, jwcrypto.jwk
import azure.mgmt.dns, azure.identity

DEFAULT_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
DEFAULT_DNS_TTL_SEC = 300

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)

def update_azure_dns(subscription, resource_group, zone, domain, value):

    log = LOGGER
    # helper function - get a DNS API client
    def _get_dns_client(subscription):
        identity = azure.identity.EnvironmentCredential()
        return azure.mgmt.dns.DnsManagementClient(identity, subscription)

    # helper function - remove zone name from domain string
    def _get_name(domain, zone):
        name = "_acme-challenge.{}".format(domain[:domain.rfind(zone)])
        log.info("Updating TXT record on %s in %s zone", name, zone)
        return name
    
    client = _get_dns_client(subscription)
    log.info("Azure DNS client initialized")
    client.record_sets.create_or_update(
        resource_group,
        zone,
        _get_name(domain, zone),
        "TXT",
        {
            "ttl": DEFAULT_DNS_TTL_SEC,
            "TXTRecords": [{"value": value}]
        }
    )
    log.info("TXT record updated")

def get_crt(private_key, regr, csr, directory_url=DEFAULT_DIRECTORY_URL):
    
    log = LOGGER
    directory, alg = None, None # global variable

    # helper function - base64 encode for jose spec
    def _b64(b):
        return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

    # helper function - make request and automatically parse json response
    def _do_request(url, data=None, err_msg="Error", depth=0):
        try:
            resp = urlopen(Request(
                url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}
            ))
            resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
        except IOError as e:
            resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
            code, headers = getattr(e, "code", None), {}
        try:
            resp_data = json.loads(resp_data) # try to parse json results
        except ValueError:
            pass # ignore json parsing errors
        if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
            raise IndexError(resp_data) # allow 100 retrys for bad nonces
        if code not in [200, 201, 204]:
            raise ValueError("{}:\nUrl: {}\nData: {}\nResponse Code: {}\nResponse: {}".format(err_msg, url, data, code, resp_data))
        return resp_data, code, headers

    # helper function - sign with cryptography module
    def _sign(private_key, alg, payload):
        if alg == "RS256":
            return private_key.sign(
                payload,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
				cryptography.hazmat.primitives.hashes.SHA256()) # RS256
        return private_key.sign(
                payload,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256())) # ES256

    # helper function - make signed requests
    def _send_signed_request(url, payload, err_msg, depth=0):
        payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
        new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
        protected = {"url": url, "alg": alg, "nonce": new_nonce, "kid": kid}
        protected64 = _b64(json.dumps(protected).encode('utf8'))
        signature64 = _b64(_sign(private_key, alg, "{}.{}".format(protected64, payload64).encode("utf-8")))
        data = json.dumps({"protected": protected64, "payload": payload64, "signature": signature64})
        try:
            return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
        except IndexError: # retry bad nonces (they raise IndexError)
            return _send_signed_request(url, payload, err_msg, depth=(depth + 1))

    # helper function - poll until complete
    def _poll_until_not(url, pending_statuses, err_msg):
        result, t0 = None, time.time()
        while result is None or result['status'] in pending_statuses:
            assert (time.time() - t0 < 3600), "Polling timeout" # 1 hour timeout
            time.sleep(0 if result is None else 2)
            result, _, _ = _send_signed_request(url, None, err_msg)
        return result

    log.info("Parsing private_key.json...")
    with open(private_key, "r") as f:
        jwk = jwcrypto.jwk.JWK.from_json(f.read())
    thumbprint = jwk.thumbprint()
    log.info("JWK thumbprint: %s", thumbprint)
    private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
        jwk.export_to_pem(private_key=True, password=None), password=None)
    log.info("Private key loaded.")

    if jwk.key_type == "RSA":
        alg = "RS256"
    elif jwk.key_type == "EC":
        alg = "ES256"
    else:
        log.error("Unknown key type")
        return None

    log.info("Parsing regr.json...")
    with open(regr, "r") as f:
        kid = json.loads(f.read())["uri"]
    log.info("Account kid: %s", kid)

    log.info("Parsing CSR...")
    with open(csr, "rb") as f:
        csr_raw = f.read()
    try:
        csr_der = cryptography.x509.load_der_x509_csr(csr_raw)
    except ValueError:
        log.error("Unable to parse CSR in DER format.")
        return None
    common_name = [csr_der.subject.get_attributes_for_oid(cryptography.x509.OID_COMMON_NAME)[0].value.strip()]
    try:
        subject_alternative_names = map(
            lambda x: x.value.strip(),
            csr_der.extensions.get_extension_for_oid(cryptography.x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        )
    except cryptography.x509.extensions.ExtensionNotFound:
        subject_alternative_names = []
    domains = list(set().union(subject_alternative_names, common_name))
    log.info("Found domains: %s", ", ".join(domains))

    log.info("Getting directory...")
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create a new order
    log.info("Creating new order...")
    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
    log.info("Order created!")

    # get the authorizations that need to be completed
    for auth_url in order['authorizations']:
        authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
        domain = authorization['identifier']['value']
        log.info("Verifying %s...", domain)

        # find the http-01 challenge and write the challenge file
        challenge = [c for c in authorization['challenges'] if c['type'] == "dns-01"][0]
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
        txt_record_value = _b64(hashlib.sha256("{}.{}".format(token, thumbprint).encode("utf-8")).digest())
        log.info("Set TXT record on _acme-challenge.%s to %s", domain, txt_record_value)

        try:
            subscription = os.environ["AZURE_SUBSCRIPTION_ID"]
            resource_group = os.environ("AZURE_DNS_ZONE_RESOURCE_GROUP")
            zone = os.environ("AZURE_DNS_ZONE")
        except KeyError as ex:
            raise KeyError("{} environment variable not set".format(ex.args[0]))
        update_azure_dns(subscription, resource_group, zone, domain, txt_record_value)

        # say the challenge is done
        _send_signed_request(challenge['url'], {}, "Error submitting challenges: {}".format(domain))
        authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {}".format(domain))
        if authorization['status'] != "valid":
            raise ValueError("Challenge did not pass for {}: {}".format(domain, authorization))
        log.info("%s verified!", domain)

    # finalize the order with the csr
    log.info("Signing certificate...")
    _send_signed_request(order['finalize'], {"csr": _b64(csr_raw)}, "Error finalizing order")

    # poll the order to monitor when it's done
    order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
    if order['status'] != "valid":
        raise ValueError("Order failed: {}".format(order))

    # download the certificate
    certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
    log.info("Certificate signed!")
    return certificate_pem

def main(argv=None):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            This script automates the process of getting a signed TLS certificate from Let's Encrypt using
            the ACME protocol. It is intented to be run in a Azure DevOps pipeline and have access to your private
            account key, so PLEASE READ THROUGH IT! It's only ~200 lines, so it won't take long.

            Example Usage:
            python acme_tiny.py --private-key ./private_key.json --regr ./regr.json --csr ./domain.csr.der > signed_chain.crt
            """)
    )
    parser.add_argument("--private-key", required=True, help="Path to your Let's Encrypt account private key")
    parser.add_argument("--regr", required=True, help="Path to your Let's Encrypt account registration info")
    parser.add_argument("--csr", default="csr.der", help="Path to your certificate signing request")
    parser.add_argument("--quiet", action="store_const", const=logging.ERROR, help="Suppress output except for errors")
    parser.add_argument("--directory-url", default=DEFAULT_DIRECTORY_URL, help="Certificate authority directory url, default is Let's Encrypt")

    args = parser.parse_args(argv)
    LOGGER.setLevel(args.quiet or LOGGER.level)
    signed_crt = get_crt(args.private_key, args.regr, args.csr, directory_url=args.directory_url)
    sys.stdout.write(signed_crt)

if __name__ == "__main__": # pragma: no cover
    main(sys.argv[1:])
