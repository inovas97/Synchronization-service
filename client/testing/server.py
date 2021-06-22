import base64
import hashlib
import socket
from Crypto import Random
from Crypto.Cipher import AES

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

string="super secure"
password="djknBDS89dHFS(*HFSD())"
enc_string=str(AESCipher(password).encrypt(string))
enc_string_2=AESCipher(password).encrypt(string)
dec_string=str(AESCipher(password).decrypt(enc_string_2))
print("This is the password " + password)
print("Decrypted string: " + string)
print("Encrypted string: " + enc_string)
print("Decrypted string (v2): " + str(dec_string))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('212.71.250.55', 8002))
sock.listen(5)
print("Listening for connections...")

conn, addr = sock.accept()
conn.send(enc_string_2)
conn.close()