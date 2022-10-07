import csv
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
k = 0
data = []


def extraction(line, k, type):
    packet = line.split(', ')

    if packet == ['[]\n']:
        return []

    try:
        packet[0] = packet[0].split('[')[1]
        packet[-1] = packet[-1].split(']')[0]
        if type == 1:
            packet[0] = packet[0].split("'")[1]
            packet[8] = packet[8].split("'")[1]
            packet[10] = packet[10].split("'")[1]
        elif type == 2:
            packet[0] = packet[0].split("'")[1]
            packet[-1] = packet[-1].split("'")[1]
        elif type == 3:
            packet[3] = packet[3].split("'")[1]

    except:
        print('Error during merging')
        print(packet)
        if input('Press enter to ignore: ') != '\n':
            exit(1)

    limit = len(packet)

    for i in range(0, limit):
        if type == 1:
            if i == 0 or i == 8 or i == 10:
                continue
            packet[i] = int(packet[i])

        elif type == 2:
            if i == 0 or i == limit - 1:
                continue

            packet[i] = int(packet[i])

        elif type == 3:
            if i == limit - 1:
                continue

            packet[i] = int(packet[i])
    if type == 1:
        if packet[10] not in clients and packet[10] not in servers:
            print(str(k) + ': ' + packet[10])
            return []

    return packet


with open("C:/Users/mailt/OneDrive/Desktop/project/tmp/totaltraffic.txt", "r") as f, open("C:/Users/mailt/OneDrive/Desktop/project/tmp/countedtraffic.txt", "r") as f1, open("C:/Users/mailt/OneDrive/Desktop/project/tmp/connection.txt", "r") as f2, open(
    "output.csv", "w") as o:
    filewriter = csv.writer(o, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
    filewriter.writerow(['IP_TYPE', 'IP_LEN', 'FR_LENGHT', 'IP_ID', 'IP_RESERVED', 'IP_DF', 'IP_MF', 'IP_OFFSET',
                         'IP_PROTO', 'IP_CHECKSUM', 'UDP_SPORT', 'UDP_DPORT', 'UDP_LEN', 'UDP_CHK', 'ICMP_TYPE',
                         'ICMP_CODE', 'ICMP_CHK', 'TCP_SPORT', 'TCP_DPORT', 'TCP_SEQ', 'TCP_ACK', 'TCP_FFIN',
                         'TCP_FSYN', 'TCP_FRST', 'TCP_FPUSH', 'TCP_FACK', 'TCP_FURG', 'COUNT_FR_SRC_DST',
                         'COUNT_FR_DST_SRC', 'NUM_BYTES_SRC_DST', 'NUM_BYTES_DST_SRC', 'NUM_PUSHED_SRC_DST',
                         'NUM_PUSHED_DST_SRC', 'NUM_SYN_FIN_SRC_DST', 'NUM_SYN_FIN_DST_SRC', 'NUM_FIN_SRC_DST',
                         'NUM_FIN_DST_SRC', 'NUM_ACK_SRC_DST', 'NUM_ACK_DST_SRC', 'NUM_SYN_SRC_DST',
                         'NUM_SYN_DST_SRC', 'NUM_RST_SRC_DST', 'NUM_RST_DST_SRC', 'COUNT_SERV_SRC_DST',
                         'COUNT_SERV_DST_SRC', 'NUM_BYTES_SERV_SRC_DST', 'NUM_BYTES_SERV_DST_SRC', 'FIRST_PACKET',
                         'FIRST_SERV_PACKET', 'CONN_STATUS', 'TYPE'])

    while True:
        line = f.readline()

        if not line:
            print('EOF')
            break

        packet1 = extraction(line, k, 1)

        if not packet1:
            continue

        k += 1

        line2 = f1.readline()
        packet2 = extraction(line2, k, 2)

        if not packet2:
            continue

        line3 = f2.readline()
        packet3 = extraction(line3, k, 3)

        if not packet3:
            continue

        for i in range(len(packet1)):
            if i == 10:
                continue
            data.append(packet1[i])

        for i in range(0, len(packet2) - 4):
            if i == 0:
                continue

            data.append(packet2[i])

        for i in range(len(packet2) - 4, len(packet2) - 1):
            data.append(packet2[i])

        for i in range(len(packet3)):
            if i == 0:
                continue

            data.append(packet3[i])

        data.append(packet2[0])
        filewriter.writerow(data)
        data = []
        #print(k)
