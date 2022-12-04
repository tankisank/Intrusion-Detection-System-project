from random import uniform, randint
import time
from datetime import datetime, timedelta
import subprocess
import sys

path = ['HTTP/httpClient.py', 'SSH/ssh.py', 'SMTP/SMTP.py', 'SNMP/SNMP.py']
clients = ['client1', 'client2', 'client3']

ips = ['10.0.1.2', '10.0.2.2', '10.0.3.2']
ports = [85, 86, 87]

attack_done = False
attack_close = False

i = int(sys.argv[1])


def curr_time():
    return datetime.strptime(str(datetime.now()), '%Y-%m-%d %H:%M:%S.%f')


end_time = curr_time() + timedelta(minutes=40)
hack_time = curr_time() + timedelta(minutes=13)
end_hack_time = hack_time + timedelta(minutes=22)


while curr_time() <= end_time:

    service = randint(0, 3)

    # Bloccante, creare un nuovo processo indipendente
    if curr_time() >= hack_time and attack_done == False:
        attack_done = True
        subprocess.Popen(
            ["mono", "/home/kali/Shared/Anomaly/LOIC/src/bin/Debug/LOIC.exe"])
        subprocess.Popen(
            ["msfconsole", "-r", "attack_config" + sys.argv[1] + ".rc", "-x", "run"])

    if curr_time() >= end_hack_time and attack_close == False:
        attack_close = True
        subprocess.Popen(["killall", "-e", "mono"])
        subprocess.Popen(["killall", "-e", "ruby"])

    # BUILD COMMAND
    if service == 0:
        subprocess.Popen(['python' , path[service] , ips[i] , str(ports[i])])
    if service == 1:
        subprocess.Popen(['python' , path[service] , ips[i]])
    if service == 2:
        subprocess.Popen(['python', path[service] , clients[i] ,ips[i]])
    if service == 3:
        subprocess.Popen(['python' , path[service] , ips[i]])
    
    time.sleep(uniform(0, 4))