import re
import sys


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



servers, clients = getlist(sys.argv[1], sys.argv[2])

first_packet = 0
first_packet_serv = 0
status = ['NEW', 'ESTABLISHED', 'CLOSED']

connections = []
first_connections = []
data = []
k = 0


def extraction(line, k):
    packet = line.split(', ')
    #print(packet)
    if packet == ['[]\n']:
        return []
    try:
        packet[0] = packet[0].split('[')[1]
        packet[-1] = packet[-1].split(']')[0]
        packet[0] = packet[0].split("'")[1]
        packet[8] = packet[8].split("'")[1]
        packet[10] = packet[10].split("'")[1]
    except:
        print("Error during packet reading")
        print("packet" + str(packet))
        if input('Press enter to ignore: ') != '\n':
            exit(1)
            
    for i in range(0, 28):
        if i == 0 or i == 8 or i == 10:
            continue

        packet[i] = int(packet[i])

    if packet[10] not in clients and packet[10] not in servers:
        print(str(k) + ': ' + packet[10])
        return []

    return packet


with open("C:/Users/mailt/OneDrive/Desktop/project/tmp/totaltraffic.txt", 'r') as f, open("C:/Users/mailt/OneDrive/Desktop/project/tmp/connection.txt", 'w') as f1:
    for line in f:
        k += 1

        if line == '[]' or line == "['']":
            continue

        packet = extraction(line, k)

        if packet == [] or packet == ['']:
            continue

        data.append(k)

        # Check FIRST_PACKET:
        # If stateless: search ID in first_connection
        # oth check TCP flag

        if packet[8] == 'UDP' or packet[8] == 'ICMP':
            if packet[3] not in first_connections or packet[3] == 0:

                if packet[10] in clients:
                    first_packet = 1

                elif packet[10] in servers:
                    first_packet_serv = 1

                first_connections.append(packet[3] + 1)
            else:
                first_connections.remove(packet[3])
                first_connections.append(packet[3] + 1)

        elif packet[8] == 'TCP':
            if (packet[-5] and not packet[-6]) or (packet[-2] and packet[-3]):

                if packet[10] in clients:
                    first_packet = 1

                elif packet[10] in servers:
                    first_packet_serv = 1

        else:
            print('Other protocol')

        data.append(first_packet)
        data.append(first_packet_serv)

       #CONN_STATUS: If stateless -> ESTABLISHED oth check TCP Flags
        if packet[8] == 'UDP' or packet[8] == 'ICMP':
            data.append(status[1])

        elif packet[8] == 'TCP':
            # FLAG SYN == 1 and FIN == 0
            if packet[-5] and not packet[-6]:
                data.append(status[0])
                
            # FLAG SYN == 1 and FIN == 1 or FIN == 1 or RST == 1
            elif (packet[-5] and packet[-6]) or (packet[-4] or packet[-5]):
                data.append(status[2])
            elif packet[-2]:
                data.append(status[1])

        f1.write(str(data))
        f1.write('\n')

        first_packet = 0
        first_packet_serv = 0
        data = []
