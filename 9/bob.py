import socket, threading, argparse, logging, random
import os, sys
from etc import generate_messages

MAC_THEN_ENCRYPT = 0
ENCRYPT_THEN_MAC = 1
ENCKEY_LENGTH = 16      # AES-128

MAC_LENGTH = 32         # HMAC-SHA256
BLOCK_LENGTH = 16       # AES block size

# string * string * bytes -> bytes
def decrypt(key, iv, encrypted):
    raise NotImplementedError("You need to implement the decrypt() function that performs AES-128 decryption")

# string * bytes * bytes -> bool
def verify(key, msg, answer):
    raise NotImplementedError("You need to implement the verify() funtion that verifies the MAC code")

# int * string * string * string -> string * bool
def ae_decrypt(ae, enckey, mackey, iv, received):
    decrypted = None
    verified = False

    if ae == MAC_THEN_ENCRYPT:
        decrypted = decrypt(enckey, iv, received)
        verified = verify(mackey, decrypted[:-MAC_LENGTH], decrypted[-MAC_LENGTH:])
        decrypted = decrypted[:-MAC_LENGTH]
        decrypted = decrypted.decode()
        return decrypted, verified
    elif ae == ENCRYPT_THEN_MAC:
        raise NotImplementedError("Please implement the encrypt-then-mac approach")


def handler(alice, ae, enckey, mackey, iv):
    challenges = generate_messages()
    rand = int(random.random() * len(challenges))
    challenge = challenges[rand]
    alice.send(challenge.encode())
    logging.info("[*] Challenge: {}".format(challenge))
    received = alice.recv(1024)
    logging.info("[*] Received: {}".format(received))
    decrypted, verified = ae_decrypt(ae, enckey, mackey, iv, received)
    if verified:
        logging.info("[*] MAC verified")
        logging.info("[*] Plaintext: {}".format(decrypted))
        if challenge == decrypted:
            logging.info("[*] Success!")
            result = "success"
        else:
            logging.info("[*] Failure!")
            result = "failure"
    else:
        logging.error("[*] Invalid MAC")
        result = "failure"
    alice.send(result.encode())
    alice.close()

def run(addr, port, ae, enckey, mackey, iv):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(2)
    logging.info("[*] Bob is Listening on {}:{}".format(addr, port))

    while True:
        alice, info = bob.accept()

        logging.info("[*] Server accept the connection from {}:{}".format(info[0], info[1]))

        handle = threading.Thread(target=handler, args=(alice, ae, enckey, mackey, iv))
        handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-w", "--ae", metavar="<authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)>", help="Authenticated encryption (0: mac-then-encrypt / 1: encrypt-then-mac)", type=int, choices=[0, 1], required=True)
    parser.add_argument("-x", "--enckey", metavar="<encryption key (AES-128)>", help="encryption key (AES-128)", type=str, required=True)
    parser.add_argument("-y", "--mackey", metavar="<MAC key (HMAC-SHA256)>", help="MAC key (HMAC-SHA256)", type=str, required=True)
    parser.add_argument("-z", "--iv", metavar="<initialization vector (16 byte)>", help="Initialization vector (16 byte)", type=str, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    if len(args.enckey) != ENCKEY_LENGTH:
        logging.error("Encryption key length error (hint: AES-128)")
        sys.exit(1)

    if len(args.iv) != BLOCK_LENGTH:
        logging.error("IV length error (hint: AES)")
        sys.exit(1)

    run(args.addr, args.port, args.ae, args.enckey, args.mackey, args.iv)

if __name__ == "__main__":
    main()
