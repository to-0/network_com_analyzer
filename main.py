# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os
import scapy.utils

protocols_dictionary = {}
icmp_messages = {}
tftp_coms = {}

class DefPacket:
    def __init__(self, mac_dest, mac_source, data, packet_number, length):
        self.mac_dest = mac_dest
        self.mac_src = mac_source
        self.data = data
        self.packet_number = packet_number
        self.ethernet_type = ""
        self.length = length
        self.network_l_protocol = None
        eth_type_hex = int(data[12:14].hex(), 16)  # zoberiem si nasledujuce 2B po mac adresach
        self.analyze_ethernet(eth_type_hex)

        if self.network_l_protocol == "IPv4":
            h_start = 0
            if self.ethernet_type == "Ethernet II":
                h_start = 14
            else:
                h_start = 17
            self.ip_src = self.data[26:30].hex()
            self.ip_dest = self.data[30:34].hex()
            v_ihl = self.data[14:15].hex()
            # version = int(v_ihl[0], 16)
            header_length = int(v_ihl[1], 16) * 4  # cele sa to posuva po 4
            ip_in_protocol = protocols_dictionary.get(
                "0x" + self.data[23:24].hex())  # toto moze byt ze tcp/udp/icmp
            # formatovanie
            if ip_in_protocol is None:
                ip_in_protocol = ["None"]
            if len(ip_in_protocol) > 1:
                self.transport_layer_protocol = " ".join(ip_in_protocol[1:])
            else:
                self.transport_layer_protocol = " ".join(ip_in_protocol)
            start = h_start + header_length
            if self.transport_layer_protocol == "TCP" or self.transport_layer_protocol == "UDP":  # chcem iba porty a protokol tie maju na
                # rovnakych miestach
                self.source_port = self.data[start:start + 2].hex()  # 2bajty chcem precitat
                self.dest_port = self.data[start + 2:start + 4].hex()
                if int(self.source_port, 16) > int(self.dest_port, 16):
                    self.transport_layer_protocol_in = protocols_dictionary.get("0x" + self.dest_port)
                    # print(self.last_layer_protocol)
                else:
                    self.transport_layer_protocol_in = protocols_dictionary.get("0x" + self.source_port)
                # formatovanie protokolu iba
                if self.transport_layer_protocol_in is not None:
                    self.transport_layer_protocol_in = " ".join(self.transport_layer_protocol_in)
                else:
                    self.transport_layer_protocol_in = "None"

                if self.transport_layer_protocol == "TCP":
                    self.tcp_flag = self.data[start+12:start+14]
                if self.transport_layer_protocol == "UDP":
                    if self.transport_layer_protocol_in == "TFTP": #nasiel som prve tftp
                        tftp_coms[self.source_port] = [int(self.ip_dest, 16), int(self.ip_src, 16)]

                    elif self.transport_layer_protocol_in == "None":
                        # skusim pozriet ci uz nemam tu komunikaciu ulozenu cez src port
                        ip_arr = tftp_coms.get(self.source_port)
                        # cize toto by bola odpoved takze prehodim ip adresy
                        if ip_arr is not None:
                            if ip_arr[0] == int(self.ip_src, 16) and ip_arr[1] == int(self.ip_dest, 16):
                                self.transport_layer_protocol_in = "TFTP"
                            elif ip_arr[0] == int(self.ip_dest, 16) and ip_arr[1] == int(self.ip_src, 16):
                                self.transport_layer_protocol_in = "TFTP"
                        ip_arr = tftp_coms.get(self.dest_port)
                        if ip_arr is not None:
                            if ip_arr[0] == int(self.ip_src, 16) and ip_arr[1] == int(self.ip_dest, 16):
                                self.transport_layer_protocol_in = "TFTP"
                            elif ip_arr[0] == int(self.ip_dest, 16) and ip_arr[1] == int(self.ip_src, 16):
                                self.transport_layer_protocol_in = "TFTP"

            elif self.transport_layer_protocol == "ICMP":
                type_m = self.data[start:start + 1].hex()
                code = self.data[start + 1:start + 2].hex()
                self.icmp_message = icmp_messages.get(str(type_m) + "/" + str(code))

        elif self.network_l_protocol == "ARP":
            if self.ethernet_type == "Ethernet II":
                h_start = 14
            else:
                h_start = 17
            protocol_type = self.data[h_start + 2:h_start + 4].hex()
            operation = self.data[h_start + 6:h_start + 8].hex()
            # tu byva asi vzdy ipv4?
            self.arp_in_protocol = protocols_dictionary.get("0x" + protocol_type)
            if self.arp_in_protocol is not None:
                self.arp_in_protocol = " ".join(self.arp_in_protocol)
            self.ip_src = self.data[h_start + 14:h_start + 18].hex()
            self.ip_dest = self.data[h_start + 24:h_start + 28].hex()
            if int(operation, 16) == 1:
                self.arp_operation = "Request"
            else:
                self.arp_operation = "Reply"

    def analyze_ethernet(self, eth_type_hex):
        if eth_type_hex >= int('0x0800', 16):  # ak je to rovne 0800 tak je to cisty ETHERNET II
            self.ethernet_type = "Ethernet II"
            self.analyze_network_layer_protocol(self.data[12:14].hex())
        else:  # je to 802.3 ale este musim zistit typ cez dalsie 2 bajty
            nb = int(self.data[14:16].hex(), 16)
            if nb == int('0xaaaa', 16):
                self.ethernet_type = "Ethernet 802.3 LLC + SNAP"
                # podla dsap sa da zistit protokol v LLC AJ SNAP
                self.analyze_network_layer_protocol(self.data[16:17].hex())
            elif nb == int('0xffff', 16):
                self.ethernet_type = "802.3 RAW"
                self.network_l_protocol = "IPX"  # ked je to raw iny protokol tam nemoze byt
            else:
                self.ethernet_type = "IEEE 802.3 LLC"
                # podla dsap sa da zistit protokol v LLC AJ SNAP
                self.analyze_network_layer_protocol(self.data[16:17].hex())

    def analyze_network_layer_protocol(self, value):
        in_protocol = protocols_dictionary.get("0x" + value)

        if in_protocol is None:
            in_protocol = ["None"]
        if len(in_protocol) > 1:
            self.network_l_protocol = " ".join(in_protocol[1:])
        else:
            self.network_l_protocol = " ".join(in_protocol)

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
        print("-" * 50)

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
        print(self.network_l_protocol)
        if self.network_l_protocol == "IPv4":
            if not (self.ip_dest == "" or self.ip_src == ""):
                print("IP cieľová: " + ip_to_output(self.ip_dest))
                print("IP zdrojová: " + ip_to_output(self.ip_src))
                print(self.transport_layer_protocol)
                if hasattr(self, 'transport_layer_protocol_in'):
                    print(self.transport_layer_protocol_in)
                    print("Zdrojový port: " + str(int(self.source_port, 16)))
                    print("Cieľový port: " + str(int(self.dest_port, 16)))
                if self.transport_layer_protocol == "TCP":
                    print(self.tcp_flag.hex())
                if self.transport_layer_protocol == "ICMP" and hasattr(self, 'icmp_message'):
                    print(self.icmp_message)
        elif self.network_l_protocol == "ARP":
            print(self.arp_operation)
            print("IP cieľová: " + ip_to_output(self.ip_dest))
            print(self.ip_dest)
            print("IP zdrojová: " + ip_to_output(self.ip_src))
            print(self.ip_src)
        self.print_data()


def main():
    load_dictionary()
    load_icmp_messages()
    print("Úlohy")
    print("1 vypíš všetky pakety")
    print("2 vypíš iba HTTP komunikáciu")
    print("3 vypíš iba HTTPs komunikáciu")
    print("4 vypíš iba Telnet komunikáciu")
    print("5 vypíš iba SSH komunikáciu")
    print("6 vypíš iba FTP-CONTROL komunikáciu")
    print("7 vypíš iba FTP-DATA komunikáciu")
    print("8 vypíš iba TFTP komunikáciu")
    print("9 vypíš ICMP komunikaciu")
    print("10 nájdi ARP dvojice")
    task = input("Číslo úlohy: ")
    while int(task) != -1:
        file_name = input("Súbor s .pcap: ")
        packets = load_packets(file_name)
        if int(task) == 1:
            task_1(packets)
        if int(task) == 2:
            task_3_1(packets)
        if int(task) == 4:
            task4_a(packets)
        if int(task) == 8:
            task4g(packets)
        if int(task) == 9:
            task4h(packets)
        if int(task) == 10:
            task4_i(packets)
        if int(task) == 17:
            test(packets)

        print("Úlohy")
        print(len(packets))
        print("1 vypíš všetky pakety")
        print("2 vypíš iba HTTP komunikáciu")
        print("3 vypíš iba HTTPs komunikáciu")
        print("4 vypíš iba Telnet komunikáciu")
        print("5 vypíš iba SSH komunikáciu")
        print("6 vypíš iba FTP-CONTROL komunikáciu")
        print("7 vypíš iba FTP-DATA komunikáciu")
        print("8 vypíš iba TFTP komunikáciu")
        print("9 vypíš ICMP komunikaciu")
        print("10 nájdi ARP dvojice")
        task = input("Číslo úlohy: ")


# zoznam ip adries vsetkych odosielajucich uzlov a ip adresa uzla ktory poslal najviac paketov
# a kolko paketov poslal
def task_3_1(packet_list):
    ip_dictionary = {}
    max_value = 0
    max_key = 0
    for packet in packet_list:  # prejdem vsetky packety, pozriem ktore su ethernet 2 a IPv4
        if packet.ethernet_type == "Ethernet II" and packet.network_l_protocol == "IPv4":
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


# analyza http komunikacie
def task4_a(packets):
    for packet in packets:
        if packet.ethernet_type == "Ethernet II" and packet.network_l_protocol == "IPv4":
            return


def task4g(packets):
    counter = 0
    processed_com = {}
    for packet in packets:
        if packet.ethernet_type == "Ethernet II" and packet.network_l_protocol == "IPv4":
            if packet.transport_layer_protocol == "UDP" and packet.transport_layer_protocol_in == "TFTP":
                counter += 1
                ask = processed_com.get(packet.source_port)
                if ask is not None:
                    continue
                ask = processed_com.get(packet.dest_port)
                if ask is not None:
                    continue
                processed_com[packet.source_port] = 1
                print("komunikacia "+str(counter))
                print("Zdrojový port: " + str(int(packet.source_port, 16)))
                print("Cieľová IP adresa " + ip_to_output(packet.ip_dest) +
                      " Zdrojová IP adresa: " +ip_to_output(packet.ip_src))
                packet.print_info()
                for packet2 in packets:
                    if packet2 == packet:
                        continue
                    if packet2.ethernet_type == "Ethernet II" and packet2.network_l_protocol == "IPv4":
                        if packet2.transport_layer_protocol == "UDP" and packet2.transport_layer_protocol_in == "TFTP":
                            if packet2.ip_dest == packet.ip_dest and packet2.ip_src == packet2.ip_src and packet2.source_port == packet.source_port:
                                packet2.print_info()
                            elif packet2.ip_dest == packet.ip_src and packet2.ip_src == packet.ip_dest and packet2.dest_port == packet.source_port:
                                packet2.print_info()




def task4h(packets):
    for packet in packets:
        if packet.transport_layer_protocol == "ICMP":
            packet.print_info()


def find_all_arps(target_ip, packets, found_ip_adress_index, index, destination_ip):
    packet_list = []
    for packet in packets:
        # packet = packets[i]
        if packet.network_l_protocol == "ARP" and packet.arp_operation == "Request" and packet.ip_dest == target_ip and packet.ip_src == destination_ip:
            # ak je to request, skontrolujem  ci je jeho packet number vacsi alebo rovny ako posledny packet
            # pre tuto komunikaciu, aby nenastala situacia ze mam request, request reply, potom znova requesty ale
            # a ja by som matchola j requesty na ktore uz prisla reply
            # rovny preto lebo ten prvy paket co som matchol ako novu komunikacius om este nepridal do listu
            if packet.packet_number >= index:
                # Tie pakety pred tymto requestom neberiem do uvahy
                packet_list.append(packet)
        if packet.network_l_protocol == "ARP" and packet.arp_operation == "Reply" and packet.ip_src == target_ip and packet.ip_dest == destination_ip:
            # ak je to reply, musim sa pozriet ci je ta reply vacsia ako cislo posledneho paketu komunikacie
            # ak by som to nekontroloval mohol by som skoncit skor napr request reply request request tak pri
            # komunikacii 2 (request, request) by som skoncil hned reply ale ta bola poslana pred requestami
            if packet.packet_number > found_ip_adress_index:
                packet_list.append(packet)
                return packet_list
    return packet_list

# ARP dvojice
def task4_i(packets):
    counter = 1
    found_ip_adresses = {}
    unmatched = []
    for packet in packets:
        if packet.network_l_protocol == "ARP" and packet.arp_operation == "Request":
            # found znaci, cislo posledneho paketu predoslej arp komunikacie na rovnaku ip adresu (konci bud reply,
            # alebo ked uz proste najdem vsetky request a ziadna reply)
            found = found_ip_adresses.get((packet.ip_dest, packet.ip_src))
            if found is not None and found >= packet.packet_number:
                continue
            # aby ked ide po sebe viacero requestov najdem reply tak aby som potom znova nevypisoval tie requesty
            # len o 1 menej a neoznacil to za novu komunikaciu

            # ulozim si teda cislo prveho paketu novej komunikacie
            # komunikacia je definovana ip_dest a ip_src, 2d dictionary to je
            found_ip_adresses[packet.ip_dest, packet.ip_src] = packet.packet_number

            # zozbieram vsetky ramce ktore su request, maju rovnaku cielovu ipcku a teda hladaju k nej mac,v ramci
            # jednej komunikacie
            packet_list = find_all_arps(packet.ip_dest, packets, found_ip_adresses[packet.ip_dest, packet.ip_src],
                                        packet.packet_number, packet.ip_src)
            # ak som nasiel este nejake requesty pred reply tak si zaznacim k tejto cielovej ip adrese (pre ktoru hladam
            # mac adresu) cislo posledneho request paketu
            if len(packet_list) > 0:
                # print("Tu som a posledny packet number je " + str(packet_list[-1].packet_number))
                # matchnem tam uplne posledny request co som nasiel zatial
                found_ip_adresses[packet.ip_dest, packet.ip_src] = packet_list[-1].packet_number
                if packet_list[-1].arp_operation != "Reply":
                    unmatched.append(packet_list)
                    continue
            print("Komunikácia číslo " + str(counter))
            print(packet.arp_operation + "," + " IP adresa " + ip_to_output(packet.ip_dest) +
                  " MAC adresa: ?")
            print("Zdrojová IP: " + ip_to_output(packet.ip_src) + " Cielova "
                  + ip_to_output(packet.ip_dest))
            for p in packet_list:
                p.print_info()
                print("")
            counter += 1
    print("Neúplné komunikácie requesty:")
    for un_com in unmatched:
        for packet in un_com:
            packet.print_info()
    print("Neuplne komunikacie replies: ")
    for packet in packets:
        if packet.network_l_protocol == "ARP" and packet.arp_operation == "Reply":
            found = found_ip_adresses.get((packet.ip_src, packet.ip_dest)) # kedze je to naopak
            if found is None or found < packet.packet_number:
                packet.print_info()


def task_1(packets):
    for packet in packets:
        packet.print_info()
    task_3_1(packets)


def load_packets(fname):
    # packets = 0
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


def test(packets):
    for i in range(390,len(packets)):
        packet = packets[i]
        packet.print_info()

if __name__ == '__main__':
    # analyze("")
    main()
