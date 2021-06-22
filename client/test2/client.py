import socket
import hashlib
from Crypto.Cipher import AES

KEY = hashlib.sha256(b"some random password").digest()
IV = b"abcdefghijklmnop" #must be 16 bits
obj_enc = AES.new(KEY, AES.MODE_CFB, IV)
obj_dec = AES.new(KEY, AES.MODE_CFB, IV)


def main():
	host = "212.71.250.55" 
	port = 8002
	soc = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	soc.connect((host, port))

	message = input("-> ")
	while message != 'q':
		message_enc = obj_enc.encrypt(message.encode('utf-8'))
		soc.send(message_enc)
		data = soc.recv(1024)
		print("received data: "+str(data))
		print("decrypting...")
		decrypted = obj_dec.decrypt(data)
		print("received from server "+str(decrypted))
		message = input("-> ")
	soc.close()


if __name__ == "__main__":
	main()