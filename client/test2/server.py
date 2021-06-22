import socket
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, SHUT_RDWR
import hashlib
from Crypto.Cipher import AES

KEY = hashlib.sha256(b"some random password").digest()	
IV = b"abcdefghijklmnop"
obj_enc = AES.new(KEY, AES.MODE_CFB, IV)
obj_dec = AES.new(KEY, AES.MODE_CFB, IV)

def echo_client(s):
	while True:
		message_enc = s.recv(1024)
		if not message_enc:
			break
		message = obj_dec.decrypt(message_enc)
		print ("recieved from connection: "+str(message))
		data = message.upper()
		print ("sending: "+str(data))
		encrypted = obj_enc.encrypt(data)
		print ("encrypting...")
		print ("encrypted data: "+str(encrypted))
		s.send(encrypted)
	s.close()

def main():
	host = "212.71.250.55"
	port = 8002

	s=socket.socket(AF_INET, SOCK_STREAM)
	s.bind((host,port))

	s.listen(1)
	while True:
		try:
			c, addr = s.accept()
			print ("connected with: "+str(addr))
			echo_client(c)
		except socket.error as e:
			print ("Error:{0}".format(e))

if __name__ == "__main__":
	main()