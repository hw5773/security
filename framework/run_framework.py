import argparse
import logging
from framework import Framework

def run(aname, klen, message):
    if aname == "rsa":
        from rsa import RSA
        algo = RSA(aname, klen)
    elif aname == "aes":
        from aes import AES
        algo = AES(aname, klen)
    framework = Framework(algo)
    framework.evaluate_elapsed_time("gen", 10)
    framework.evaluate_elapsed_time("enc", 10)
    framework.evaluate_elapsed_time("dec", 10)

    framework.evaluate_cpu_time("gen", 10)
    framework.evaluate_cpu_time("enc", 10)
    framework.evaluate_cpu_time("dec", 10)

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--algorithm", metavar="<algorithm>", help="Algorithm", type=str, required=True)
    parser.add_argument("-k", "--length", metavar="<key length>", help="RSA key length", type=int, required=True)
    parser.add_argument("-m", "--message", metavar="<message to be encrypted>", help="Message to be encrypted", type=str)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.algorithm, args.length, args.message)

if __name__ == "__main__":
    main()
