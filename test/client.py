import os
import socket
import time
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 8002))
object_path = "text.txt"
fd = open(object_path, "rb")
filesize = os.path.getsize(object_path)
sock.send(bytes(str(filesize),"utf-8"))
response=sock.recv(10)
print(response)
file_bytes = fd.read(10)
file_list = list(file_bytes)
while len(file_list) > 0:
    sock.send(file_bytes)
    response = sock.recv(10)
    file_bytes = fd.read(10)
    file_list = list(file_bytes)
    
