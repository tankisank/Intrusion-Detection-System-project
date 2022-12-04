import os
import socket
import time
import sys


HOSTS, PORT = ['10.0.1.2', '10.0.2.2', '10.0.3.2']
PORT=[88,89,90]

pid_figlio = [0,0,0]
s = []

for i in range(0,3):
    s.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    s[i].bind((HOSTS[i], PORT[i]))
    s[i].listen()

#È una soluzione tappabuchi ma in linux non ho modo di condividere le variabili    
time.sleep(10)

for i in range(0, 3):
    pid_figlio[i] = os.fork()
    if pid_figlio[i] == 0:
        connection, client_addr = s[i].accept()
        connection.sendall('OK'.encode('UTF-8'))
        connection.sendall(str(i).encode('UTF-8'))
    else:
        os.system('python HTTP/httpServer.py ' + str(i))
        
sys.exit()