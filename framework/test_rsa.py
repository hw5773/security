import argparse
import logging
from rsa import RSA

def run(klen, message):
    rsa = RSA("rsa", klen)
    rsa.key_generation()
    #rsa.print_keypair()

    ciphertext = rsa.encryption(plaintext=message)
    logging.info("ciphertext: {}".format(ciphertext))
    plaintext = rsa.decryption(ciphertext=ciphertext)
    logging.info("plaintext: {}".format(plaintext))

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--length", metavar="<rsa key length>", help="RSA key length", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message to be encrypted>", help="Message to be encrypted", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.length, args.message)

if __name__ == "__main__":
    main()
