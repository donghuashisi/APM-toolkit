import socket
import os

ETH_P_ALL = 3

interface = os.popen("sudo ifconfig | grep 'NS'").read().split(':')[0]
dst = b'\x08\x00\x27\xdd\xd7\x43'  # destination MAC address
src = b'\x08\x00\x27\x8e\x75\x44'  # source MAC address
proto = b'\x88\xb5' 
               # ethernet frame type
payload = 'Hi'.encode()            # payload
src_ip = "10.0.0.1" 
dst_ip = "20.0.0.1" 

src_ip = socket.inet_aton(src_ip)
dst_ip = socket.inet_aton(dst_ip)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sock.bind((interface, 0))
sock.sendall(dst + src + proto + payload)
s.close()

