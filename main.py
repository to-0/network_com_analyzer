# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os
import scapy.utils

# import scapy.all as scapy

protocols_dictionary = {}
icmp_messages = {}


class DefPacket:
    def __init__(self, mac_source, mac_dest, data, packet_number, length):
        self.mac_src = mac_source
        self.mac_dest = mac_dest
        self.data = data
        self.packet_number = packet_number
        self.ethernet_type = ""
        self.length = length
        self.inner_protocol = None
        eth_type_hex = int(data[12:14].hex(), 16)  # zoberiem si nasledujuce 2B po mac adresach
        if eth_type_hex >= int('0x0800', 16):  # ak je to rovne 0800 tak je to cisty ETHERNET II
            self.ethernet_type = "Ethernet II"
            self.analyze_network_layer_protocol(data[12:14].hex(), 14)
        else:  # je to 802.3 ale este musim zistit typ cez dalsie 2 bajty
            nb = int(data[14:16].hex(), 16)
            if nb == int('0xaaaa', 16):
                self.ethernet_type = "Ethernet 802.3 LLC + SNAP"
                self.analyze_network_layer_protocol(data[16:17].hex(), 17)  # podla dsap sa da zistit protokol v LLC AJ SNAP
            elif nb == int('0xffff', 16):
                self.ethernet_type = "802.3 RAW"
                self.inner_protocol = "IPX"  # ked je to raw iny protokol tam nemoze byt
            else:
                self.ethernet_type = "IEEE 802.3 LLC"
                self.analyze_network_layer_protocol(data[16:17].hex(), 17)  # podla dsap sa da zistit protokol v LLC AJ SNAP

    def analyze_network_layer_protocol(self, value, h_start):
        in_protocol = protocols_dictionary.get("0x" + value)

        if in_protocol is None:
            in_protocol = ["None"]
        if len(in_protocol) > 1:
            self.inner_protocol = " ".join(in_protocol[1:])
            self.inner_protocol_port = in_protocol[0]
        else:
            self.inner_protocol = " ".join(in_protocol)

        if self.inner_protocol == "IPv4":
            self.ip_src = self.data[26:30].hex()
            self.ip_dest = self.data[30:34].hex()
            v_ihl = self.data[14:15].hex()
            version = int(v_ihl[0], 16)
            header_length = int(v_ihl[1], 16) * 4  # cele sa to posuva po 4
            ip_in_protocol = protocols_dictionary.get(
                "0x" + self.data[23:24].hex())  # toto moze byt ze tcp/udp/icmp
            if ip_in_protocol is None:
                ip_in_protocol = ["None"]
            if len(ip_in_protocol) > 1:
                self.ip_in_protocol = " ".join(ip_in_protocol[1:])
                self.ip_in_protocol_port = ip_in_protocol[0]
            else:
                self.ip_in_protocol = " ".join(ip_in_protocol)
            self.analyze_transport_l_protocol(header_length, h_start+header_length)
        elif self.inner_protocol == "ARP":
            protocol_type = self.data[h_start + 2:h_start + 4].hex()
            operation = self.data[h_start + 6:h_start + 8].hex()
            self.arp_in_protocol = protocols_dictionary.get("0x" + protocol_type)
            if self.arp_in_protocol is not None:
                self.arp_in_protocol = " ".join(self.arp_in_protocol)
            self.ip_src = self.data[h_start + 14:h_start + 18].hex()
            self.ip_dest = self.data[h_start + 24:h_start + 28].hex()
            if int(operation, 16) == 1:
                self.arp_operation = "Request"
            else:
                self.arp_operation = "Reply"

    def analyze_transport_l_protocol(self, prev_header_length, h_start):
        start = 14 + prev_header_length
        if self.ip_in_protocol == "TCP" or self.ip_in_protocol == "UDP":
            self.source_port = self.data[h_start:h_start + 2].hex()  # 2bajty chcem precitat
            #print(int(self.source_port, 16))
            self.dest_port = self.data[h_start + 2:h_start + 4].hex()
            #print(int(self.dest_port, 16))
            if int(self.source_port, 16) > int(self.dest_port, 16):
                self.transport_layer_protocol = protocols_dictionary.get("0x" + self.dest_port)
                #print(self.last_layer_protocol)
            else:
                self.transport_layer_protocol = protocols_dictionary.get("0x" + self.source_port)
        else:
            type = self.data[h_start:h_start+1].hex()
            code = self.data[h_start+1:h_start+2].hex()
            self.icmp_message = icmp_messages.get(str(type)+"/"+str(code))

    def print_data(self):
        s = ""
        i = 1
        for byte in self.data:
            holder = hex(byte)
            s += holder[2:].zfill(2) + " "
            if (i % 8) == 0:
                s += " "
            if (i % 16) == 0:
                print(s)
                s = ""
            i += 1
        if (i % 16) != 0:
            print(s)

        print("-"*50)

    def print_info(self):
        print('Rámec ' + str(self.packet_number))
        print("Dĺžka rámca " + str(len(self.data)))
        real_length = len(self.data) + 4
        if real_length < 64:
            real_length = 64

        print("Skutočná dĺžka rámca " + str(real_length))
        print(self.ethernet_type)
        mac_source_str = ""
        mac_dest_str = ""
        mac_len = int(len(self.mac_src))  # 12 lebo je to v stringu
        for i in range(0, len(self.mac_dest) - 2, 2):
            mac_dest_str += self.mac_dest[i:i + 2] + "."
            mac_source_str += self.mac_src[i:i + 2] + "."
        mac_dest_str += self.mac_dest[mac_len - 2: mac_len]
        mac_source_str += self.mac_src[mac_len - 2: mac_len]
        print("MAC zdrojová " + mac_source_str.upper())
        print("MAC cieľová " + mac_dest_str.upper())
        print(self.inner_protocol)
        if self.inner_protocol == "IPv4":
            if not (self.ip_dest == "" or self.ip_src == ""):
                print("IP cieľová: " + ip_to_output(self.ip_dest))
                print("IP zdrojová: " + ip_to_output(self.ip_src))
                print(self.ip_in_protocol)
                if hasattr(self, 'transport_layer_protocol'):
                    print(self.transport_layer_protocol)
                    print("Zdrojový port: " + str(int(self.source_port, 16)))
                    print("Cieľový port: " + str(int(self.dest_port, 16)))
                if self.ip_in_protocol == "ICMP" and hasattr(self, 'icmp_message'):
                    print(self.icmp_message)
        elif self.inner_protocol == "ARP":
            print(self.arp_operation)
            print("IP cieľová: " + ip_to_output(self.ip_dest))
            print("IP zdrojová: " + ip_to_output(self.ip_src))
        self.print_data()


def main():
    load_dictionary()
    load_icmp_messages()
    task = ""
    while task != "end":
        print("Úlohy")
        print("1 vypíš všetky pakety")
        print("4 vypíš iba HTTP pakety")
        print("5 nájdi ARP dvojice")
        task = input("Číslo úlohy: ")
        file_name = input("Súbor s .pcap: ")
        packets = load_packets(file_name)
        if int(task) == 1:
            task_1(packets)
        if int(task) == 3:
            task_3_1(packets)
        if int(task) == 4:
            task4_a(packets)
        if int(task) == 5:
            task4_i(packets)


def task_3_1(packet_list): #zoznam ip adries vsetkych odosielajucich uzlov a ip adresa uzla ktory poslal najviac paketov
    #a kolko paketov poslal
    ip_dictionary = {}
    max_value = 0
    max_key = 0
    for packet in packet_list:  # prejdem vsetky packety, pozriem ktore su ethernet 2 a IPv4
        if packet.ethernet_type == "Ethernet II" and packet.inner_protocol == "IPv4":
            # zoberiem si ip adresu zdrojovu a cez dictionary si ukladam pocet vyskytov tejto ip adresy
            ip_adress = packet.ip_src
            if ip_dictionary.get(ip_adress) is not None:
                ip_dictionary[ip_adress] += 1
            else:
                ip_dictionary[ip_adress] = 1
    for key, value in ip_dictionary.items():
        print(ip_to_output(key))
        if value > max_value:
            max_value = value
            max_key = key
    print("Adresa uzla s najväčším počtom odoslaných paketov ")
    print(str(ip_to_output(max_key)) + " " + str(max_value))

def task4_a(packets): #analyza http komunikacie
    for packet in packets:
        if packet.ethernet_type == "Ethernet II" and packet.inner_protocol == "IPv4":
            return

def task4_i(packets): #ARP dvojice
    counter = 0
    for packet in packets:
        if packet.inner_protocol == "ARP":
            #print(packet.arp_operation)

                for packet2 in packets:
                    if packet2.packet_number == packet.packet_number or packet2.inner_protocol != "ARP":
                        continue
                    if packet2.arp_operation == "Reply":
                        if packet2.ip_src == packet.ip_dest:
                            counter += 1
                            if packet.arp_operation == "Request":
                                print("Komunikácia číslo " + str(counter))
                                print(packet.arp_operation + "," + " IP adresa " + ip_to_output(packet.ip_dest) +
                                      " MAC adresa: ?")
                                print("Zdrojová IP: " + ip_to_output(packet.ip_src) + "Cielova "
                                      + ip_to_output(packet.ip_dest))
                                packet.print_info()

                            print(packet2.arp_operation + "," + " IP adresa " + ip_to_output(
                                packet2.ip_src) + " MAC adresa: "+packet2.mac_src)
                            print("Zdrojoá IP: " + ip_to_output(packet2.ip_src) + " Cieľová "
                                  + ip_to_output(packet2.ip_dest))
                            packet2.print_info()
                            break


def task_1(packets):
    for packet in packets:
        packet.print_info()
    task_3_1(packets)


def load_packets(fname):
    packets = 0
    if fname == "":
        packets = scapy.utils.rdpcap("vzorky/trace-1.pcap")
    if not os.path.isfile("vzorky/" + fname):
        packets = scapy.utils.rdpcap("vzorky\eth-1.pcap")
    else:
        packets = scapy.utils.rdpcap("vzorky/" + fname)
    packet_number = 1
    my_packet_list = []
    for packet in packets:
        packet = bytes(packet)
        my_packet_list.append(DefPacket(packet[0:6].hex(), packet[6:12].hex(), packet, packet_number, len(packet)))
        packet_number += 1
    return my_packet_list


def ip_to_output(ip):
    res = ""
    length = len(ip)
    for i in range(0, length, 2):
        res += str(int(ip[i:i + 2], 16))
        if i + 2 < length:
            res += "."
    return res


protocols = []


def load_dictionary():
    f = open("hodnoty")
    lines = f.readlines()
    global protocols_dictionary
    for line in lines:
        arr = line.split()
        if line[0][0] != "#":
            protocols_dictionary[arr[0]] = arr[1:]

def load_icmp_messages():
    f = open("icmp_types.txt")
    lines = f.readlines()
    global icmp_messages
    for line in lines:
        arr = line.split()
        if line[0][0] != "#":
            icmp_messages[arr[0]] = arr[1:]

if __name__ == '__main__':
    # analyze("")
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
