import re

data = []
traffic = []
n_pack = 0
skip = 0

def tcp_packet(temp_traffic, n_line):
    TCP_Seq = 0
    if n_line == 4:
        for j in range(0, 7):
            data.append(0)
        TCP_Sport = int(temp_traffic[3], base=16) + int(temp_traffic[2], base=16) * int(pow(16, 2))
        TCP_Dport = int(temp_traffic[5], base=16) + int(temp_traffic[4], base=16) * int(pow(16, 2))

        """
        print('TCP SourcePort: ' + str(TCP_Sport) + '\n' +
                'TCP DestinationPort: ' + str(TCP_Dport))
        """

        data.append(TCP_Sport)
        data.append(TCP_Dport)

        TCP_Seq = int(temp_traffic[7], base=16) * int(pow(16, 4)) + int(temp_traffic[6], base=16) * int(pow(16, 3))
    if n_line == 5:
        TCP_Seq += int(temp_traffic[1], base=16) + int(temp_traffic[0], base=16) * int(pow(16, 2))
        TCP_Ack = int(temp_traffic[5], base=16) + int(temp_traffic[4], base=16) * int(pow(16, 2)) + int(temp_traffic[3],
                                                                                                        base=16) * int(
            pow(16, 3)) + int(temp_traffic[2], base=16) * int(pow(16, 4))
        TCP_Ffin = int(temp_traffic[7], base=16) & 0x1
        TCP_Fsyn = int((int(temp_traffic[7], base=16) & 0x2) / 2)
        TCP_Frst = int((int(temp_traffic[7], base=16) & 0x4) / 4)
        TCP_Fpush = int((int(temp_traffic[7], base=16) & 0x8) / 8)
        TCP_Fack = int((int(temp_traffic[7], base=16) & 0x10) / 16)
        TCP_Furg = int((int(temp_traffic[7], base=16) & 0x20) / 32)

        """print('Seq: ' + str(TCP_Seq))
        print('Ack: ' + str(TCP_Ack))
        print('TCP_Ffin: {}, TCP_Fsyn: {}, TCP_Frst: {}, TCP_Fpush: {}, TCP_Fack: {}, TCP_Furg: {}'.format(TCP_Ffin, TCP_Fsyn, TCP_Frst, TCP_Fpush, TCP_Fack, TCP_Furg))
        """

        data.append(TCP_Seq)
        data.append(TCP_Ack)
        data.append(TCP_Ffin)
        data.append(TCP_Fsyn)
        data.append(TCP_Frst)
        data.append(TCP_Fpush)
        data.append(TCP_Fack)
        data.append(TCP_Furg)
    else:
        pass


def udp_packet(temp_traffic, n_line):
    if n_line == 4:
        UDP_Sport = int(temp_traffic[3], base=16) + int(temp_traffic[2], base=16) * int(pow(16, 2))
        UDP_Dport = int(temp_traffic[5], base=16) + int(temp_traffic[4], base=16) * int(pow(16, 2))
        UDP_Len = int(temp_traffic[7], base=16) + int(temp_traffic[6], base=16) * int(pow(16, 2))

        """print('UDP SourcePort: ' + str(UDP_Sport) + '\n' +
              'UDP DestinationPort: ' + str(UDP_Dport) + '\n' +
              'UDP Lenght: ' + str(UDP_Len))"""

        data.append(UDP_Sport)
        data.append(UDP_Dport)
        data.append(UDP_Len)

    elif n_line == 5:
        UDP_Checksum = int(temp_traffic[1], base=16) + int(temp_traffic[0], base=16) * int(pow(16, 2))

        # print('UDP Checksum: ' + str(UDP_Checksum))

        data.append(UDP_Checksum)

        for j in range(0, 13):
            data.append(0)
    else:
        pass


def icmp_packet(temp_traffic, n_line):
    if n_line == 4:
        for j in range(0, 4):
            data.append(0)

        ICMP_Type = int(temp_traffic[2], base=16)
        ICMP_Code = int(temp_traffic[3], base=16)
        ICMP_Checksum = int(temp_traffic[5], base=16) + int(temp_traffic[4], base=16) * int(pow(16, 2))

        """print('ICMP Type: ' + str(ICMP_Type))
        print('ICMP Code: ' + str(ICMP_Code))
        print('ICMP Checksum: ' + str(ICMP_Checksum))"""

        data.append(ICMP_Type)
        data.append(ICMP_Code)
        data.append(ICMP_Checksum)

        for j in range(0, 10):
            data.append(0)
    else:
        pass


temp_traffic = []
n_line = 0
with open("totaltraffic.c", "r") as f, open("C:/Users/mailt/OneDrive/Desktop/project/tmp/totaltraffic.txt", "w") as f1:
    while True:
        # Read line
        line = f.readline()

        # Check EOF
        if not line:
            break

        # Check blank line or packet's first line (comment)
        if line.strip() and not bool(re.search("^(\/\*) Frame \(*[0-9]* bytes\) (\*\/)$", line)):

            # Check End of Line
            if bool(re.search("};\n", line)):

                f1.write(str(data))
                f1.write('\n')
                skip = 0
                n_pack += 1
                n_line = 0
                data = []
                continue

            if skip:
                continue

            if bool(re.search("\/\* Reassembled SMTP \(11 bytes\) \*\/", line)):
                skip = 1
                continue

            # Check array C declaration
            if bool(re.search("static const unsigned char pkt*[0-9]*\[*[0-9]*\] = {", line)):
                dim = re.split("[\[\]]", line)[1]
                continue

            # Analyze packet: it has 8 columns composed by hexadecimal bytes and 16 ASCII bytes
            temp_traffic = line.split(', ')

            # Remove 16 ASCII bytes alongside the data offset (last item)
            for i in range(0, len(temp_traffic)):
                if re.search("\/\* .* \*\/", temp_traffic[i]):
                    if re.split(" *\/\* .* \*\/", temp_traffic[i])[0] == '':
                        temp_traffic.pop(i)
                    else:
                        temp_traffic[i] = re.split(" *\/\* .* \*\/", temp_traffic[i])[0]

            if n_line == 1:
                try:
                    if temp_traffic[4] == '0x08' and temp_traffic[5] == '0x00':
                        # print('Type of IP: Ipv4')
                        ip = 4
                        Header_Len = int((int(temp_traffic[6], base=16) & 0xf) * 32 / 8)
                        # print('Header_Len: ' + str(Header_Len))
                    elif temp_traffic[5] == '0xdd':
                        ip = 6
                    else:
                        ip = 0
                        # print('Protocol: ' + str(n_pack))
                        print(temp_traffic)

                except:
                    print('Exception during extraction: ' + str(n_pack))
                    if input('Press enter to ignore: ') != '\n':
                        exit(1)

            if n_line == 2 and ip == 4:
                Total_len = int(temp_traffic[1], base=16) + int(temp_traffic[0], base=16) * int(pow(16, 2))
                # print('Total Len: ' + str(Total_len))

                ID = int(temp_traffic[3], base=16) + int(temp_traffic[2], base=16) * int(pow(16, 2))
                # print('ID: ' + str(ID))

                Reserved = int((int(temp_traffic[4], base=16) & 0x80) / 128)
                DF = int((int(temp_traffic[4], base=16) & 0x40) / 64)
                MF = int((int(temp_traffic[4], base=16) & 0x20) / 32)
                Offset = int(temp_traffic[5], base=16) + int(int(temp_traffic[4], base=16) & 0x1f) * int(pow(16, 2))

                """print('FLAGS: \n' +
                      'Reserved: ' + str(Reserved) + '\n' +
                      "Don't Fragments: " + str(DF) + '\n' +
                      "More Fragments: " + str(MF))
                print('OFFSET: ' + str(Offset))"""

                if int(temp_traffic[7], base=16) == 0x01:
                    Protocol = 'ICMP'
                    # print('Protocol: ICMP')
                elif int(temp_traffic[7], base=16) == 0x06:
                    Protocol = 'TCP'
                    # print('Protocol: TCP')
                elif int(temp_traffic[7], base=16) == 0x11:
                    Protocol = 'UDP'
                    # print('Protocol: UDP')
                else:
                    Protocol = 'unknown'
                    #print('Protocol UNKNOWN, ID: ' + str(n_pack))

                if Protocol != 'unknown':
                    data.append('Ipv4')
                    data.append(Header_Len)
                    data.append(Total_len)
                    data.append(ID)
                    data.append(Reserved)
                    data.append(DF)
                    data.append(MF)
                    data.append(Offset)
                    data.append(Protocol)

            if n_line == 3 and ip == 4 and Protocol != 'unknown':
                Checksum = int(temp_traffic[1], base=16) + int(temp_traffic[0], base=16) * pow(16, 2)
                try:
                    Source_IP = str(int(temp_traffic[2], base=16)) + '.' + str(
                        int(temp_traffic[3], base=16)) + '.' + str(
                        int(temp_traffic[4], base=16)) + '.' + str(int(temp_traffic[5], base=16))
                    data.append(Checksum)
                    data.append(Source_IP)
                except:
                    print("Error during checksum and Source_IP extraction")
                    print(temp_traffic)
                    print(n_pack)
                    if input('Press enter to ignore: ') != '\n':
                        exit(1)

                """print('CHECKSUM: ' + str(Checksum))
                print('SOURCE IP: ' + Source_IP)"""

            # Enter in header protocol used
            if n_line > 3 and ip == 4:
                if Protocol == 'ICMP':
                    icmp_packet(temp_traffic, n_line)
                elif Protocol == 'TCP':
                    tcp_packet(temp_traffic, n_line)
                elif Protocol == 'UDP':
                    udp_packet(temp_traffic, n_line)

            # Next line
            n_line += 1