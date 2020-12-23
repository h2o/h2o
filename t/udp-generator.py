#!/usr/bin/python3

import sys
import socket

if len(sys.argv) < 4:
	print('Usage: %s [server] [port] [input...]' % sys.argv[0])
	sys.exit(1)

server = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((server, port))

for f in sys.argv[3:]:
	file = open(f, mode='rb')
	msg = file.read()
	s.send(msg)
