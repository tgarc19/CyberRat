import socket

hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)
print("Your IP:", local_ip)
