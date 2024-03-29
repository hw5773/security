from ecdsa import VerifyingKey, NIST256p
import socket
import argparse
import logging
import base64
import os
import sys
import json
import hashlib
import time
import datetime

# verify the signature in "signed" (JSON object) based on the public key in "cert" (JSON object)
def verify_signature(signed, cert):
    ret = True
    reason = "success"
    if "signature" not in signed:
        ret = False
        reason = "no signature in signed"
    elif "public key" not in cert:
        ret = False
        reason = "no public key in cert"
    else:
        tbv = {}
        keys = list(signed.keys())
        logging.debug("before: {}".format(keys))
        keys.remove("signature")
        logging.debug("after: {}".format(keys))

        for k in keys:
            tbv[k] = signed[k]

        try:
            vk = VerifyingKey.from_pem(cert["public key"].encode())
        except:
            ret = False
            reason = "error in loading the public key from cert"
            return ret, reason

        js = json.dumps(tbv)
        logging.debug("tbv: {}".format(js))
        logging.debug("signature: {}".format(signed["signature"]))
        sig = base64.b64decode(signed["signature"].encode())

        try:
            ret = vk.verify(sig, js.encode(), hashfunc=hashlib.sha256)
        except:
            ret = False
            reason = "verification failure"

    return ret, reason

# chain (a list of JSON objects) * trusted (a list of JSON objects) -> bool * string
def chain_validation(chain, trusted):
    ret = False
    reason = "not implemented"
    return ret, reason

# string * chain (a list of JSON objects) -> bool * string
def name_validation(url, chain):
    ret = False
    reason = "not implemented"
    return ret, reason

def revocation_checking(chain, crl, ocsp):
    curr = int(time.time())
    curr = datetime.datetime.fromtimestamp(curr)

    # 1. checking validity period (please complete the following logic)
    for cert in chain:
        not_before = datetime.datetime.strptime(cert["not before"], "%Y-%m-%d")
        not_after = datetime.datetime.strptime(cert["not after"], "%Y-%m-%d")

        # TODO: check the validity period of the certificate and set the appropriate values for "ret" and "reason"
        ret = False
        reason = "not implemented"

    if not ret:
        return ret, reason
    
    # 2. checking revocation (crl or ocsp)
    ret = False
    reason = "not implemented"
    return ret, reason

def validate_certificate(url, chain, trusted, crl, ocsp):
    ret = False

    chain_verified, reason = chain_validation(chain, trusted)
    if chain_verified:
        name_verified, reason = name_validation(url, chain)

        if name_verified: 
            revocation_verified, reason = revocation_checking(chain, crl, ocsp)

            if revocation_verified:
                ret = True

    return ret, reason

def load_crls(cdir):
    crl = {}
    clst = [f.split(".")[0] for f in os.listdir(cdir)]

    for ca in clst:
        with open("{}/{}.crl".format(cdir, ca), "r") as f:
            crl[ca] = json.loads(f.read())

    return crl

def load_trusted_root_ca(tdir):
    trusted = {}
    tlst = [f.split(".")[0] for f in os.listdir(tdir)]

    for ca in tlst:
        with open("{}/{}.crt".format(tdir, ca), "r") as f:
            trusted[ca] = json.loads(f.read())

    return trusted

def run(addr, port, rfile, cdir, tdir):
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("[*] Client is connected to {}:{}".format(addr, port))

    # crl: ca name -> crl
    crl = load_crls(cdir)

    # trusted: ca name -> ca's certificate
    trusted = load_trusted_root_ca(tdir)

    with open(rfile, "r") as f:
        for line in f:
            if line.strip() == '':
                break
            url = line.strip()
            alice.send(url.encode())
            logging.info("[*] Sent: {}".format(url))
            received = alice.recv(2048).decode()
            logging.debug("[*] Received: {}".format(received))
            js = json.loads(received)
            cstr = js["chain"]
            chain = []
            for cert in cstr:
                chain.append(json.loads(cert))
            ocsp = js["ocsp"]
            if ocsp != "none":
                ocsp = json.loads(ocsp)
            verified, reason = validate_certificate(url, chain, trusted, crl, ocsp)
            logging.info("[*] Result of Certificate Validation ({}): {} ({})".format(url, verified, reason))

    alice.send("finished".encode())

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-r", "--request", metavar="<request file>", help="Request file name", type=str, required=True)
    parser.add_argument("-c", "--crl", metavar="<crl directory>", help="CRL directory", type=str, required=True)
    parser.add_argument("-t", "--trusted", metavar="<trusted ca directory>", help="Trusted CA directory", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if not os.path.exists(args.request):
        logging.error("The request file does not exist: {}".format(args.request))
        sys.exit(1)

    if not os.path.exists(args.crl):
        logging.error("The directory specified for CRL does not exist: {}".format(args.crl))
        sys.exit(1)

    if not os.path.exists(args.trusted):
        logging.error("The directory specified for trusted root CA does not exist: {}".format(args.trusted))
        sys.exit(1)

    run(args.addr, args.port, args.request, args.crl, args.trusted)
    
if __name__ == "__main__":
    main()
