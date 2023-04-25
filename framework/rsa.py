import base64
from algorithm import Algorithm
from Crypto.PublicKey import RSA as rsa
from Crypto.Cipher import PKCS1_OAEP

class RSA(Algorithm):
    def __init__(self, name, klen):
        super().__init__(name)
        self.params["klen"] = klen
        self.asymmetric = True

    def key_generation(self, **kwargs):
        klen = self.params["klen"]
        key = rsa.generate(klen)
        private_key = key
        public_key = key.publickey()
        self.keypair["private"] = private_key
        self.keypair["public"] = public_key

    def print_keypair(self):
        private = self.keypair["private"].export_key()
        public = self.keypair["public"].export_key()
        print ("Print {}'s keypair ===".format(self.name))
        print (" - private key: {}".format(private))
        print (" - public key: {}".format(public))

    def encryption(self, **kwargs):
        if not "plaintext" in kwargs:
            encrypted = None
        else:
            plaintext = kwargs["plaintext"]
            public = self.keypair["public"]
            oaep = PKCS1_OAEP.new(public)
            encrypted = base64.b64encode(oaep.encrypt(plaintext.encode())).decode()
        return encrypted

    def decryption(self, **kwargs):
        if not "ciphertext" in kwargs:
            decrypted = None
        else:
            ciphertext = kwargs["ciphertext"]
            private = self.keypair["private"]
            oaep = PKCS1_OAEP.new(private)
            decrypted = oaep.decrypt(base64.b64decode(ciphertext)).decode()
        return decrypted
