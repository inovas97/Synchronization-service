import socket
import base64
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('212.71.250.55', 8002))

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

password="djknBDS89dHFS(*HFSD())"
data=sock.recv(4096)
decoded=AESCipher(password).decrypt(data.decode('utf-8'))
print(str(decoded))
sock.close()