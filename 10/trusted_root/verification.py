import json
import base64
import hashlib
from ecdsa import VerifyingKey, NIST256p

with open("root1.crt", "r") as f:
    crt = f.read()

js = json.loads(crt)
print ("subject: {}".format(js["subject"]))
print ("issuer: {}".format(js["issuer"]))

tbv = {}
tbv["subject"] = js["subject"]
tbv["issuer"] = js["issuer"]
tbv["public key"] = js["public key"]

vk = VerifyingKey.from_pem(js["public key"].encode())
verified = vk.verify(base64.b64decode(js["signature"].encode()), hashlib.sha256(json.dumps(tbv).encode()).digest())
print ("verified: {}".format(verified))
