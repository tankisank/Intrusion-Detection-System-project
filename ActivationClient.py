import socket
import sys
import os
import time

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((sys.argv[1], int(sys.argv[2])))
    signal = s.recv(1024)
    
    if signal.decode('UTF-8') == 'OK':
        n = s.recv(1024).decode('UTF-8')
        time.sleep(2)
        os.system('python RUN.py ' + n)