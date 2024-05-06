import json
import hashlib
import base64
from ecdsa import SigningKey, NIST256p

sk = SigningKey.generate(curve=NIST256p)
sk_str = sk.to_string()
print ("sk: {}".format(sk_str))

with open("root2_sk.pem", "wb") as f:
    f.write(sk_str)

vk = sk.verifying_key
vk_str = vk.to_string()
print ("vk (str): {}".format(vk_str))

vk_pem = vk.to_pem().decode()
print("vk (pem): {}".format(vk_pem))

tbs = {}
tbs["subject"] = "Root CA 2"
tbs["issuer"] = "Root CA 2"
tbs["public key"] = vk_pem

tbs_str = json.dumps(tbs)
print ("tbs: {}".format(tbs_str))

signature = base64.b64encode(sk.sign(hashlib.sha256(tbs_str.encode()).digest()))
print ("signature: {}".format(signature))

cert = {}
cert["subject"] = tbs["subject"]
cert["issuer"] = tbs["issuer"]
cert["public key"] = tbs["public key"]
cert["signature"] = signature.decode()

with open("root2.crt", "w") as f:
    f.write(json.dumps(cert))
