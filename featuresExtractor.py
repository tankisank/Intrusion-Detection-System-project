import sys
import os
import re


def getlist(server_list, client_list):
    try:
        server_l = server_list.split(',')
        clients_l = client_list.split(',')
        server_l[0] = server_l[0].split('[')[1]
        clients_l[0] = clients_l[0].split('[')[1]
        server_l[-1] = server_l[-1].split(']')[0]
        clients_l[-1] = clients_l[-1].split(']')[0]
    except:
        print('Input bad formatted')
        exit(1)
        
    for i in range(0, len(server_l)):
        if re.search("^([0-9]+(\.[0-9]+)+(\.[0-9]+)(\.[0-9]))$", server_l[i]):
            continue
        print('Bad address: ')
        print(server_l[i])
        exit(1)
    
    for i in range(0, len(clients_l)):
        if re.search("^([0-9]+(\.[0-9]+)+(\.[0-9]+)(\.[0-9]))$", clients_l[i]):
            continue
        print('Bad address: ')
        print(clients_l[i])
        exit(1)
    
    return server_l, clients_l


if len(sys.argv) != 3: 
    print('Error: script needs 3 parameters')
    exit(1)

servers, clients = getlist(sys.argv[1], sys.argv[2])
#open extractor
print("Start main features extraction")
if os.system("python extractor.py"):
    print("Error during the extraction")
    exit(2)

#open counterHistory
print("Start counterHistory extraction")
if os.system("python counterHistory.py " + sys.argv[1] + " " + sys.argv[2]):
    print("Error during counterHistory extraction")
    exit(3)
    
#open connection
print("Start connection extraction")
if os.system("python connection.py " + sys.argv[1] + " " + sys.argv[2]):
    print("Error during connection extraction")
    exit(4)

#open mergefile
print("Start merging output files")
if os.system("python mergefile.py " + sys.argv[1] + " " + sys.argv[2]):
    print("Error during merging files")
    exit(5)

