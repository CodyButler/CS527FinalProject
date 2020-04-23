#!/usr/bin/python3

import socket
import sys

PORT = 55555 
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('127.0.0.1', PORT)
print ('starting server on %s port %s' % server_address)
sock.bind(server_address)

print("UDP server is up and listening...")

while True:
	data , addr = sock.recvfrom(1024)
	print ("received message : %d", data)

