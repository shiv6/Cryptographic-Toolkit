import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, DES, Blowfish, ARC4, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
import base64

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class DESCipher(object):

    def __init__(self, key):
        self.bs = DES.block_size
        self.key = self.processKey(key)

    def processKey(self, key):
        while len(key) < 8:
            key = key + key
        return bytes(key[:8], 'utf-8')

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(DES.block_size)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[DES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class BlowfishCipher(object):

    def __init__(self, key):
        self.bs = Blowfish.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(Blowfish.block_size)
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:Blowfish.block_size]
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[Blowfish.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class ARC4Cipher(object):
    def __init__(self, key):
        self.key = SHA.new(bytes(key, 'utf-8')).digest()

    def encrypt(self, raw):
        cipher = ARC4.new(self.key)
        msg = cipher.encrypt(bytes(raw, 'utf-8'))
        return base64.b64encode(msg)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = ARC4.new(self.key)
        raw = cipher.decrypt(enc)
        return raw.decode()


class RSA_OAEP(object):
    def generate_key(self):
        keyPair = RSA.generate(3072)
        pubKey = keyPair.publickey()
        pubKeyPEM = pubKey.exportKey().decode('ascii')
        privKeyPEM = keyPair.exportKey().decode('ascii')
        return pubKeyPEM, privKeyPEM

    def encrypt(self, raw, keyPEM):
        pubKey = RSA.import_key(bytes(keyPEM, 'utf-8'))
        encryptor = PKCS1_OAEP.new(pubKey)
        enc = encryptor.encrypt(bytes(raw, 'utf-8'))
        return base64.b64encode(enc)

    def decrypt(self, enc, keyPEM):
        key = RSA.import_key(bytes(keyPEM, 'utf-8'))
        decryptor = PKCS1_OAEP.new(key)
        enc = base64.b64decode(enc)
        raw = decryptor.decrypt(enc)
        return raw


class DSA_Signature(object):
    def generate_key(self):
        keyPair = DSA.generate(2048)
        pubKey = keyPair.publickey()
        pubKeyPEM = pubKey.exportKey().decode('ascii')
        privKeyPEM = keyPair.exportKey().decode('ascii')
        return pubKeyPEM, privKeyPEM


    def sign_message(self, text, key):
        privKey = DSA.import_key(bytes(key, 'utf-8'))
        hash_obj = SHA256.new(bytes(text, 'utf-8'))
        signer = DSS.new(privKey, 'fips-186-3')
        signature = signer.sign(hash_obj)
        return base64.b64encode(signature)

    def varify_message(self, text, signature, key):
        pubKey = DSA.import_key(bytes(key, 'utf-8'))
        hash_obj = SHA256.new(bytes(text, 'utf-8'))
        verifier = DSS.new(pubKey, 'fips-186-3')
        signature = base64.b64decode(signature)
        try:
            verifier.verify(hash_obj, signature)
            return True
        except ValueError:
            return False

if __name__ == '__main__':
    pub, priv = DSA_Signature().generate_key()
    print(pub)
    print(priv)
    sign = DSA_Signature().sign_message("Shivank Shukla", priv)
    print(sign)
    res = DSA_Signature().varify_message("Shivank Shukla", sign, pub)
    print(res)

    # pub, priv = RSA_OAEP().generate_key()
    # print('pub: ', pub)
    # print('priv: ', priv)
    # enc = RSA_OAEP().encrypt('Shivank Shukla', pub)
    # print(enc)
    # raq = RSA_OAEP().decrypt(enc, priv)
    # print(raq)

    # cipher = ARC4Cipher("ABCDEjdkjdsl").encrypt("Shivank Shukla")
    # print(cipher)
    # raw = ARC4Cipher("ABCDEjdkjdsl").decrypt(cipher)
    # print(raw)