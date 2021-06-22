import socket 

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('127.0.0.1', 8002))
sock.listen(5)
print("Listening for connections...")

conn, addr = sock.accept()
filesize = int(conn.recv(1024).decode("utf-8"))
print("filesize ", filesize)
conn.send(bytes("ok","utf-8"))
received_data = 0
while filesize > received_data:
    bts = conn.recv(10)
    print(len(bts))
    print(bts)
    conn.send(bytes("ok", "utf-8"))
    received_data += len(bts)
    
conn.close()