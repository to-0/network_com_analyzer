# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import sys

import scapy.utils
import os
from constants import *

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

        if self.network_l_protocol == IPV4:
            h_start = 0
            if self.ethernet_type ==  ETHERNET2:
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
            if self.transport_layer_protocol == TCP or self.transport_layer_protocol == UDP:  # chcem iba porty a protokol tie maju na
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

                if self.transport_layer_protocol == TCP:
                    self.tcp_flag = self.data[start + 12:start + 14].hex()
                if self.transport_layer_protocol == UDP:
                    if self.transport_layer_protocol_in == TFTP:  # nasiel som prve tftp
                        tftp_coms[self.source_port] = [int(self.ip_dest, 16), int(self.ip_src, 16)]

                    elif self.transport_layer_protocol_in == "None":
                        # skusim pozriet ci uz nemam tu komunikaciu ulozenu cez src port
                        ip_arr = tftp_coms.get(self.source_port)
                        # cize toto by bola odpoved takze prehodim ip adresy
                        if ip_arr is not None:
                            if ip_arr[0] == int(self.ip_src, 16) and ip_arr[1] == int(self.ip_dest, 16):
                                self.transport_layer_protocol_in = TFTP
                            elif ip_arr[0] == int(self.ip_dest, 16) and ip_arr[1] == int(self.ip_src, 16):
                                self.transport_layer_protocol_in = TFTP
                        ip_arr = tftp_coms.get(self.dest_port)
                        if ip_arr is not None:
                            if ip_arr[0] == int(self.ip_src, 16) and ip_arr[1] == int(self.ip_dest, 16):
                                self.transport_layer_protocol_in = TFTP
                            elif ip_arr[0] == int(self.ip_dest, 16) and ip_arr[1] == int(self.ip_src, 16):
                                self.transport_layer_protocol_in = TFTP

            elif self.transport_layer_protocol == ICMP:
                type_m = self.data[start:start + 1].hex()
                code = self.data[start + 1:start + 2].hex()
                self.icmp_message = icmp_messages.get(str(type_m) + "/" + str(code))

        elif self.network_l_protocol == ARP:
            if self.ethernet_type == ETHERNET2:
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
            self.ethernet_type = ETHERNET2
            self.analyze_network_layer_protocol(self.data[12:14].hex())
        else:  # je to 802.3 ale este musim zistit typ cez dalsie 2 bajty
            nb = int(self.data[14:16].hex(), 16)
            if nb == int('0xaaaa', 16):
                self.ethernet_type = ETHLLC_SNAP
                # podla dsap sa da zistit protokol v LLC AJ SNAP myslim ale este si to overim
                self.analyze_network_layer_protocol(self.data[16:17].hex())
            elif nb == int('0xffff', 16):
                self.ethernet_type = RAW
                self.network_l_protocol = IPX  # ked je to raw iny protokol tam nemoze byt
            else:
                self.ethernet_type = ETHLLC
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
        # ak tam este nieco zostalo
        if s != "":
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
                # if self.transport_layer_protocol == "TCP":
                #     print(self.tcp_flag)
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
    out = input("Do suboru (a) alebo do konzoly(b)? ")

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
    # while int(task) != -1:
    file_name = input("Cesta k súboru s .pcap: ")
    packets = load_packets(file_name)
    if out == "a":
        sys.stdout = open('vystup.txt', 'w', encoding="utf-8")
    if int(task) == 1:
        task_1(packets)
    if int(task) == 2:
        task4_af(packets, HTTP)
    if int(task) == 3:
        task4_af(packets, HTTPS)
    if int(task) == 4:
        task4_af(packets, TELNET)
    if int(task) == 5:
        task4_af(packets, SSH)
    if int(task) == 6:
        task4_af(packets, FTP_CONTROL)
    if int(task) == 7:
        task4_af(packets, FTP_DATA)
    if int(task) == 8:
        task4g(packets)
    if int(task) == 9:
        task4h(packets)
    if int(task) == 10:
        task4_i(packets)
    if out == "a":
        sys.stdout.close()


# zoznam ip adries vsetkych odosielajucich uzlov a ip adresa uzla ktory poslal najviac paketov
# a kolko paketov poslal
def task_3_1(packet_list):
    ip_dictionary = {}
    max_value = 0
    max_key = 0
    for packet in packet_list:  # prejdem vsetky packety, pozriem ktore su ethernet 2 a IPv4
        if packet.ethernet_type == ETHERNET2 and packet.network_l_protocol == IPV4:
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


def filter_packets_by_tcpin_protocol(packets, protocol):
    filtered_list = []
    for packet in packets:
        if packet.ethernet_type == ETHERNET2 and packet.network_l_protocol == IPV4 \
                and packet.transport_layer_protocol == TCP and packet.transport_layer_protocol_in == protocol:
            filtered_list.append(packet)
    return filtered_list


def check_packets_handshake_open(p1, p2, p3):
    flags = bin(int(p1.tcp_flag, 16))
    # potrebujem iba 12 bitov od konca na flagy
    flags = flags[6:]
    flags = int(flags, 2)
    syn, ack, fin, rst = 0, 0, 0, 0
    # hladam prvu zacatu komunikaci
    if (flags & 2) == 2:
        syn = 1
    flags = bin(int(p2.tcp_flag, 16))
    # potrebujem iba 12 bitov od konca na flagy
    flags = flags[6:]
    flags = int(flags, 2)
    syn2, ack2 = 0, 0
    # hladam prvu zacatu komunikaciu
    if (flags & 2) == 2:
        syn2 = 1
    if (flags & 16) == 16:
        ack2 = 1

    flags = bin(int(p3.tcp_flag, 16))
    # potrebujem iba 12 bitov od konca na flagy
    flags = flags[6:]
    flags = int(flags, 2)
    ack3 = 0
    # hladam prvu zacatu komunikaciu
    if (flags & 16) == 16:
        ack3 = 1

    if p2.ip_src == p1.ip_dest and p2.ip_dest == p1.ip_src and p3.ip_src == p1.ip_src:
        if syn == 1 and syn2 == 1 and ack2 == 1 and ack3 == 1:
            return True
    return False


def check_closing_handshake(p1, p2, p3, p4):
    i = 0
    acks = [0, 0, 0, 0]
    fins = [0, 0, 0, 0]
    rsts = [0, 0, 0, 0]
    while i < 4:
        p = p1
        if i == 0:
            p = p1
        if i == 1:
            p = p2
        if i == 2:
            p = p3
        if i == 4:
            p = p4
        flags = bin(int(p.tcp_flag, 16))
        flags = flags[6:]
        flags = int(flags, 2)
        if (flags & 16) == 16:
            acks[i] = 1
        if (flags & 4) == 4:
            rsts[i] = 1
        if (flags & 1) == 1:
            fins[i] = 1
        i += 1
    # RESET iba
    if rsts[3] == 1:
        return True
    # RESET a ACK
    if rsts[2] == 1 and acks[3] == 1:
        if p3.ip_src == p4.ip_dest:
            return True
    # PRVY SPOSOB
    if fins[0] == 1 and acks[0] == 0 and acks[1] == 1 and fins[2] == 1 and acks[2] == 1 and acks[3] == 1:
        if p1.ip_src == p2.ip_dest and p2.ip_src == p3.ip_src and p4.ip_src == p1.ip_src:
            return True
    # DRUHY SPOSOB
    if fins[0] == 1 and acks[1] == 1 and fins[2] == 1 and acks[3] == 1:
        if p1.ip_src == p2.ip_dest and p2.ip_src == p3.ip_src and p4.ip_src == p1.ip_src:
            return True
    # TRETI SPOSOB
    if fins[2] == 1 and rsts[3] == 1:
        if p3.ip_src == p4.ip_dest:
            return True
    # PIATY sposOB
    if fins[1] == 1 and rsts[2] == 1 and acks[3] == 1:
        if p3.ip_src == p2.ip_dest and p3.ip_src == p4.ip_src:
            return True
    if fins[1]== 1 and acks[1]==1 and fins[2]==1 and acks[2]==1 and acks[3]==1:
        if p2.ip_src == p3.ip_dest and p3.ip_src == p2.ip_src:
            return True
    if fins[2] == 1 and rsts[3] == 1:
        if p3.ip_src == p4.ip_dest:
            return True
    if fins[0] ==1 and acks[0]==1 and fins[1]==1 and acks[1]==1 and acks[2]==1 and acks[3]==1:
        if p1.ip_src == p2.ip_dest and p1.ip_src == p3.ip_src and p2.ip_src == p4.ip_src:
            return True
    return False


# analyza http komunikacie
def task4_af2(packets, protocol):
    http_packets = filter_packets_by_tcpin_protocol(packets, protocol)
    compl_comms = []
    incompl_coms = []
    comms = []
    i = 0
    comm = []
    while i < len(http_packets):
        packet = http_packets[i]
        comm.append(packet)
        http_packets.remove(packet)
        k = i
        # dam si dokopy komunikacie podla ip adries a portov
        while k < len(http_packets):
            p2 = http_packets[k]
            # klient
            if p2.ip_src == packet.ip_src and p2.ip_dest == packet.ip_dest and p2.dest_port == packet.dest_port and p2.source_port == packet.source_port:
                comm.append(p2)
                http_packets.remove(p2)
                continue
            # je to SERVER
            if p2.ip_src == packet.ip_dest and p2.ip_dest == packet.ip_src and p2.dest_port == packet.source_port and p2.source_port == packet.dest_port:
                comm.append(p2)
                http_packets.remove(p2)
                continue
            k += 1
        comms.append(comm)
        # i += 1
        comm = []
    for comm in comms:
        if len(comm) >= 3:
            p1 = comm[0]
            if p1.packet_number == 286:
                print("EW")
            p2 = comm[1]
            p3 = comm[2]
            if not check_packets_handshake_open(p1, p2, p3):
                continue
            if len(comm) == 3 and check_packets_handshake_open(p1, p2, p3):
                incompl_coms.append(comm)
                continue
        p4 = comm[-1]
        p3 = comm[-2]
        p2 = comm[-3]
        p1 = comm[-4]
        if check_closing_handshake(p1, p2, p3, p4):
            compl_comms.append(comm)
        else:
            incompl_coms.append(comm)
    counter = 1
    for comm in compl_comms:
        print("Kompletná komunikácia číslo " + str(counter))
        for packet in comm:
            packet.print_info()
        counter += 1
        # break # lebo vraj iba jednu komunikaciu
    counter = 1
    for comm in incompl_coms:
        if len(comm) > 0:
            print("Nekompletná komunikácia číslo " + str(counter))
        for packet in comm:
            packet.print_info()
        counter += 1


def task4_af(packets, protocol):
    http_packets = filter_packets_by_tcpin_protocol(packets, protocol)
    compl_comms = []
    incompl_coms = []
    comms = []
    i = 0
    comm = []

    while i < len(http_packets):
        packet = http_packets[i]
        comm.append(packet)
        http_packets.remove(packet)
        k = i
        # dam si dokopy komunikacie podla ip adries
        while k < len(http_packets):
            p2 = http_packets[k]
            #klient
            if p2.ip_src == packet.ip_src and p2.ip_dest == packet.ip_dest and p2.dest_port == packet.dest_port and p2.source_port == packet.source_port:
                comm.append(p2)
                http_packets.remove(p2)
                continue
            # je to SERVER
            if p2.ip_src == packet.ip_dest and p2.ip_dest == packet.ip_src and p2.dest_port == packet.source_port and p2.source_port == packet.dest_port:
                comm.append(p2)
                http_packets.remove(p2)
                continue
            k += 1
        comms.append(comm)
        comm = []
    temp = []
    for comm in comms:
        i = 0
        temp = []
        handshake_steps = 0
        while i < len(comm):
            p1 = comm[i]
            #print(p1.packet_number)
            flags = bin(int(p1.tcp_flag, 16))
            #potrebujem iba 12 bitov od konca na flagy
            flags = flags[6:]
            flags = int(flags,  2)
            syn, ack, fin, rst = 0, 0, 0, 0
            # hladam prvu zacatu komunikaciu
            if (flags & 16) == 16:
                ack = 1
            if (flags & 2) == 2:
                syn = 1
            if (flags & 4) == 4:
                rst = 1
            if (flags & 1) == 1:
                fin = 1
            end_com_steps = 0
            # mam prvy paket ktory zacina handshake
            if syn == 1 and handshake_steps != 3:
                # znacim si iba kroky handshaku nastal prvy
                handshake_steps = 1
                temp.append(p1)
                comm.remove(p1)
                j = i
                # hladam handshake
                while j < len(comm):
                    p2 = comm[j]
                    flags_p2 = bin(int(p2.tcp_flag, 16))
                    flags_p2 = flags_p2[6:]
                    flags_p2 = int(flags_p2, 2)

                    # NASTAVENIE FLAGOV
                    syn_p2, ack_p2, rst_p2, fin_p2 = 0, 0, 0, 0
                    if (flags_p2 & 16) == 16:
                        ack_p2 = 1
                    if (flags_p2 & 2) == 2:
                        syn_p2 = 1
                    if (flags_p2 & 4) == 4:
                        rst_p2 = 1
                    #temp.append(p2)
                    #comm.remove(p2)
                    # ak mi tam pride random reset tak este pozriem ci za tym neni ack ale je to kazdopadne
                        # KONTROLA DOKONCENIA HANDSHAKE
                        # mam paket co ma ack asyn ale musim pozriet ci to je odpoved na ten moj co zacina komunikaciu
                    if ack_p2 == 1 and syn_p2 == 1 and handshake_steps == 1:
                        # je to odpoved
                        if p2.ip_src == p1.ip_dest and p2.ip_dest == p1.ip_src and p2.dest_port == p1.source_port and p2.source_port == p1.dest_port:
                            handshake_steps = 2
                            temp.append(p2)
                            comm.remove(p2)
                            continue
                        # posledny krok handshaku odpovedam serveru tiez ack
                    elif ack_p2 == 1 and handshake_steps == 2:
                        if p2.ip_src == p1.ip_src and p2.ip_dest == p1.ip_dest and p2.dest_port == p1.dest_port and p2.source_port == p1.source_port:
                            handshake_steps = 3
                            i=j-1
                            temp.append(p2)
                            comm.remove(p2)
                            #print("Maam handshake")
                            break
                    j += 1
                # neni tam handshake celu tu komunikaciu odignorujem
                if j >= len(comm) and handshake_steps != 3:
                    # vyskocim z vonkajsieho while a i < ako dlzka comm cize odignorujem iba komunikaciu
                    # alebo teda co z nej ostalo...
                    temp = []
                    break
            # ked mam handshake
            elif handshake_steps == 3:
                # vidim prvy fin flag tak sa vnorim a pozeram ci mi neskonci komunikacia
                # print("Handshake steps == 3")
                if fin == 1:
                    temp.append(p1)
                    comm.remove(p1)
                    j = i
                    #print("Idem druhy cyklus")
                    # hladam koniec komunikacie
                    end_type = 0
                    while j < len(comm):
                        p2 = comm[j]
                        flags_p2 = bin(int(p2.tcp_flag, 16))
                        flags_p2 = flags_p2[6:]
                        flags_p2 = int(flags_p2, 2)
                        # NASTAVENIE FLAGOV
                        ack_p2, rst_p2, fin_p2 = 0, 0, 0
                        if (flags_p2 & 16) == 16:
                            ack_p2 = 1
                        if (flags_p2 & 4) == 4:
                            rst_p2 = 1
                        if (flags_p2 & 1) == 1:
                            fin_p2 = 1
                        # kompletna
                        if rst_p2 == 1:
                            temp.append(p2)
                            comm.remove(p2)
                            if len(comm) > 1 and j+1 < len(comm):
                                flags_p = bin(int(comm[j+1].tcp_flag, 16))
                                flags_p = flags_p[6:]
                                flags_p = int(flags_p, 2)
                                if (flags_p & 16) == 16:
                                    temp.remove(comm[j+1])
                                    comm.remove(comm[j+1])
                            compl_comms.append(temp)
                            temp = []
                            i = -1
                            break
                        # prvy typ
                        if ack == 1 and end_com_steps == 0:
                            end_com_steps = 1
                            end_type = 1
                        # je to odpoved
                        if p2.ip_src == p1.ip_dest and p2.ip_dest == p1.ip_src and p2.dest_port == p1.source_port and p2.source_port == p1.dest_port:
                            # PRVY TYP
                            if ack_p2 == 1 and end_type == 1 and end_com_steps == 1:
                                if fin_p2 == 1:
                                    end_type = 6
                                temp.append(p2)
                                comm.remove(p2)
                                end_com_steps = 2
                                continue
                            elif fin_p2 == 1 and ack_p2 == 1 and end_com_steps == 2 and end_type == 1:
                                temp.append(p2)
                                comm.remove(p2)
                                end_com_steps = 3
                                continue
                            # DRUHY TYP
                            elif ack_p2 == 1 and end_com_steps == 0:
                                end_com_steps = 1
                                end_type = 2
                                temp.append(p2)
                                comm.remove(p2)
                                continue
                            elif fin_p2 == 1 and end_type == 2 and end_com_steps == 1:
                                end_com_steps = 2
                                temp.append(p2)
                                comm.remove(p2)
                                continue
                            # PIATY toto asi netreba
                            # elif rst_p2 == 1 and end_type == 0:
                            #     end_type = 5
                            #     temp.append(p2)
                            #     comm.remove(p2)
                            #     continue
                            # # piaty na konci nie je ack
                            # elif end_type == 5:
                            #     temp.append(p2)
                            #     comm.remove(p2)
                            #     compl_comms.append(temp)
                            #     handshake_steps = 0
                            #     i=0
                            #     temp = []
                            #     break
                            # elif ack_p2 == 1 and end_type == 6 and end_com_steps == 3:
                            #     temp.append(p2)
                            #     comm.remove(p2)
                            #     compl_comms.append(temp)
                            #     handshake_steps = 0
                            #     i = 0
                            #     temp = []
                            #     break
                        # je to klient
                        elif p2.ip_src == p1.ip_src and p2.ip_dest == p1.ip_dest and p2.dest_port == p1.dest_port and p2.source_port == p1.source_port:
                            #PRVY TYP
                            if ack_p2 == 1 and end_type == 1 and end_com_steps == 3:
                                temp.append(p2)
                                comm.remove(p2)
                                compl_comms.append(temp)
                                handshake_steps = 0
                                temp = []
                                i = 0
                                break
                            # DRUHY TYP
                            elif ack_p2 == 1 and end_type == 2 and end_com_steps == 2:
                                complete = True
                                temp.append(p2)
                                comm.remove(p2)
                                compl_comms.append(temp)
                                handshake_steps = 0
                                temp = []
                                i = 0
                                break
                            # TRETI TYP
                            elif end_type == 0 and rst_p2 == 1:
                                temp.append(p2)
                                comm.remove(p2)
                                compl_comms.append(temp)
                                handshake_steps = 0
                                temp = []
                                i = 0
                                break
                            # # PIATY  ak je na konci este ack ktory tam nemusi ale byt
                            # elif end_type == 5 and ack_p2 == 1:
                            #     temp.append(p2)
                            #     comm.remove(p2)
                            #     compl_comms.append(temp)
                            #     temp = []
                            #     handshake_steps = 0
                            #     i = 0
                            #     break
                            # # ak je to ale end type 5 ale nemam acknowledgement navyse tak koncim
                            # elif end_type == 5:
                            #     temp.append(p2)
                            #     comm.remove(p2)
                            #     compl_comms.append(temp)
                            #     temp = []
                            #     break
                            elif ack_p2==1 and end_type==6 and end_com_steps == 2:
                                temp.append(p2)
                                comm.remove(p2)
                                # este sa moze stat ze mam po tomto dalsi ack z druhej strany ale nemoze mat syn
                                if j+1 <len(comm):
                                    p3 = comm[j+1]
                                    if p3.ip_src == p2.ip_dest:
                                        flags_p = bin(int(p3.tcp_flag, 16))
                                        flags_p = flags_p[6:]
                                        flags_p = int(flags_p, 2)
                                        if (flags_p & 16) == 16 and (flags_p & 2) != 2:
                                            temp.append(p3)
                                            comm.remove(p3)
                                compl_comms.append(temp)
                                temp = []
                                handshake_steps = 0
                                temp = []
                                i = -1
                                break
                                #compl_comms.append(temp)
                                #temp = []
                                #break
                        j += 1
                    #print("Skoncil som druhy cyklus")
                    # ak to je piaty typ skoncenia komunikacie ale na konci nebol ack, cize som docital
                    if end_type == 5 and j >= len(comm):
                        compl_comms.append(temp)
                        temp = []

                    if j >= len(comm) and len(temp)!=0:
                        # if end_type == 6 and end_com_steps == 3:
                        #     compl_comms.append(temp)
                        # else:
                        incompl_coms.append(temp)
                        temp = []
                        break
                elif rst == 1: # rst este musim pozriet ci nemam ack z opacnej strany
                    temp.append(p1)
                    comm.remove(p1)
                    if (i+1) < len(comm):
                        p2 = comm[i+1]
                        flags_p2 = bin(int(p2.tcp_flag, 16))
                        flags_p2 = flags_p2[6:]
                        flags_p2 = int(flags_p2, 2)
                        ack_p2 = 0
                        if (flags_p2 & 16) == 16:
                            ack_p2 = 1
                        if p2.ip_src == p1.ip_dest:
                            temp.append(p2)
                            comm.remove(p2)
                            compl_comms.append(temp)
                            temp = []
                            handshake_steps = 0
                            i = 0
                    else:
                        compl_comms.append(temp)
                        temp = []
                        i = 0
                elif syn != 1:
                    temp.append(p1)
                    comm.remove(p1)
                    continue
            i += 1
        if i >= len(comm) and handshake_steps == 3:
            incompl_coms.append(temp)


    counter = 1
    for comm in compl_comms:
        print("Kompletná komunikácia číslo "+str(counter))
        for packet in comm:
            packet.print_info()
        counter +=1
        #break # lebo vraj iba jednu komunikaciu
    counter = 1
    for comm in incompl_coms:
        if len(comm) > 0:
            print("Nekompletná komunikácia číslo " + str(counter))
        for packet in comm:
            packet.print_info()
        counter += 1
        #break

def find_one_tftp_communication(comslist, ip_src, ip_dest, port_src, port_dst, index, packets):
    # idem iba dalej od toho paketu

    length = len(packets)
    i = index
    while i < length:
        packet = packets[i]
        if port_dst == 69:
            comslist.append(packet)
            packets.remove(packet)
            length -= 1
            continue
        if packet.ip_src == ip_src and packet.ip_dest == ip_dest and packet.source_port == port_src and packet.dest_port == port_dst:
            comslist.append(packet)
            packets.remove(packet)
            length -= 1
            continue
        elif packet.ip_dest == ip_src and packet.ip_src == ip_dest and packet.dest_port == port_src and packet.source_port == port_dst:
            comslist.append(packet)
            packets.remove(packet)
            length -= 1
            continue
        i += 1


# TFTP KOMUNIKACIA


def task4g(packets):
    counter = 0
    # list vsetkych komunikacii
    comms = []
    tftps = []
    for packet in packets:
        if packet.ethernet_type==ETHERNET2 and packet.network_l_protocol == IPV4:
            if packet.transport_layer_protocol == UDP and packet.transport_layer_protocol_in == TFTP:
                tftps.append(packet)
    # pozbieram si vsetky tftp pakety
    i = 0
    # list komunikacie
    list_com = []
    while i < len(tftps):
        packet = tftps[i]
        # zacina sa komunikacia hodim prvy paket a pokracujem dalej
        if int(packet.dest_port, 16) == 69:
            list_com.append(packet)
            tftps.remove(packet)
            continue
        # dal som tam uz ten pociatocny paket s portom 69
        if len(list_com) > 0:
            # ak tam uz je prvy paket co zacina tu komunikaciu na porte tak si ho zoberiem
            # a celu komunikaciu hladam vzhladom na jeho ip adresy a source port, dest port zoberiem toho paketu
            # kde teraz som, ak sa budu lisit iba tam tak to nevadi vobec lebo ten sa len tak random zmeni myslim
            p = list_com[0]
            find_one_tftp_communication(list_com, p.ip_src, p.ip_dest, p.source_port, packet.source_port,
                                        i, tftps)
        else:
            find_one_tftp_communication(list_com, packet.ip_src, packet.ip_dest, packet.source_port, packet.dest_port,
                                        i, tftps)
        comms.append(list_com)
        list_com = []
    for communication in comms:
        counter += 1
        print("Komunikácia číslo " + str(counter))
        length_list = len(communication)
        j = 0
        for packet in communication:
            j += 1
            if length_list > 20 and (10 < j < (length_list - 10)):
                if j == 11:
                    print("...")
                continue
            packet.print_info()


def task4h(packets):  # ICMP
    icmps = []
    for packet in packets:
        if packet.ethernet_type == ETHERNET2 and packet.network_l_protocol == IPV4:
            if packet.transport_layer_protocol == ICMP:
                icmps.append(packet)
    coms = []
    i = 0
    while i < len(icmps):
        p1 = icmps[i]
        j = i
        com = []
        com.append(p1)
        icmps.remove(p1)
        while j < len(icmps):
            p2 = icmps[j]
            if p1.ip_src == p2.ip_src and p1.ip_dest == p2.ip_dest:
                com.append(p2)
                icmps.remove(p2)
                continue
            elif p1.ip_src == p2.ip_dest and p1.ip_dest == p2.ip_src:
                com.append(p1)
                icmps.remove(p2)
                continue
            j += 1
        coms.append(com)
        com = []
        i += 1
    print(len(coms))
    counter = 1
    for comm in coms:
        print("Komunikacia cislo "+str(counter))
        for p in comm:
            p.print_info()
        counter +=1


def find_arp_pair(target_ip, packets, found_ip_adress_index, index, destination_ip):
    packet_list = []
    length = len(packets)
    for i in range(index, length, 1):
        packet = packets[i]
        if packet.network_l_protocol == ARP and packet.arp_operation == "Request" and packet.ip_dest == target_ip and packet.ip_src == destination_ip:
            # ak je to request, skontrolujem  ci je jeho packet number vacsi alebo rovny ako posledny packet
            # pre tuto komunikaciu, aby nenastala situacia ze mam request, request reply, potom znova requesty ale
            # a ja by som matchola j requesty na ktore uz prisla reply
            # rovny preto lebo ten prvy paket co som matchol ako novu komunikacius om este nepridal do listu
            if packet.packet_number >= found_ip_adress_index:
                # Tie pakety pred tymto requestom neberiem do uvahy
                packet_list.append(packet)
        if packet.network_l_protocol == ARP and packet.arp_operation == "Reply" and packet.ip_src == target_ip and packet.ip_dest == destination_ip:
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
    i = 0
    while i < len(packets):
        packet = packets[i]
        if packet.packet_number == 232:
            print("hey")
        if packet.network_l_protocol == ARP and packet.arp_operation == "Request":
            # found znaci, cislo posledneho paketu predoslej arp komunikacie na rovnaku ip adresu (konci bud reply,
            # alebo ked uz proste najdem vsetky request a ziadna reply)
            found = found_ip_adresses.get((packet.ip_dest, packet.ip_src))
            if found is not None and found > packet.packet_number:
                i += 1
                continue
            # aby ked ide po sebe viacero requestov najdem reply tak aby som potom znova nevypisoval tie requesty
            # len o 1 menej a neoznacil to za novu komunikaciu

            # ulozim si teda cislo prveho paketu novej komunikacie
            # komunikacia je definovana ip_dest a ip_src, 2d dictionary to je
            found_ip_adresses[packet.ip_dest, packet.ip_src] = packet.packet_number

            # zozbieram vsetky ramce ktore su request, maju rovnaku cielovu ipcku a teda hladaju k nej mac,v ramci
            # jednej komunikacie
            packet_list = []
            packet_list = find_arp_pair(packet.ip_dest, packets, found_ip_adresses[packet.ip_dest, packet.ip_src],
                                        i, packet.ip_src)
            # ak som nasiel este nejake requesty pred reply tak si zaznacim k tejto cielovej ip adrese (pre ktoru hladam
            # mac adresu) cislo posledneho request paketu
            if len(packet_list) > 0:
                # print("Tu som a posledny packet number je " + str(packet_list[-1].packet_number))
                # matchnem tam uplne posledny request co som nasiel zatial
                found_ip_adresses[packet.ip_dest, packet.ip_src] = packet_list[-1].packet_number
                if packet_list[-1].arp_operation != "Reply":
                    unmatched.append(packet_list)
                    # continue
                else:
                    print("Komunikácia číslo " + str(counter))
                    print(packet.arp_operation + "," + " IP adresa " + ip_to_output(packet.ip_dest) +
                          " MAC adresa: ?")
                    print("Zdrojová IP: " + ip_to_output(packet.ip_src) + " Cielova "
                          + ip_to_output(packet.ip_dest))
                    length_list = len(packet_list)
                    j = 0
                    for p in packet_list:
                        j += 1
                        if length_list > 20 and (10 < j < (length_list - 10)):
                            if j == 11:
                                print("...")
                            continue
                        p.print_info()
                        print("")
                    counter += 1
            else:
                l = []
                l.append(packet)
                unmatched.append(l)
        i += 1
    print("Neúplné komunikácie requesty:")
    length_list = len(unmatched)
    j = 0
    for un_com in unmatched:
        for packet in un_com:
            j += 1
            # if length_list > 20 and (10 < j < (length_list - 10)):
            #    if j == 11:
            #        print("...")
            #    continue
            packet.print_info()

    length_list = len(unmatched)
    j = 0
    unmatched_replies = []
    for packet in packets:
        if packet.network_l_protocol == ARP and packet.arp_operation == "Reply":
            found = found_ip_adresses.get((packet.ip_src, packet.ip_dest))  # kedze je to naopak
            if found is None or found < packet.packet_number:
                unmatched_replies.append(packet)
                # packet.print_info()
    length_list = len(unmatched_replies)
    j = 0
    if length_list > 0:
        print("Neuplne komunikacie replies: ")
    for packet in unmatched_replies:
        if length_list > 20 and (10 < j < (length_list - 10)):
            if j == 11:
                print("...")
            continue
        packet.print_info()


def task_1(packets):
    # indexes = [8,42,463,1293]
    for packet in packets:
        # if packet.packet_number not in indexes:
        #    continue
        packet.print_info()
    task_3_1(packets)


def load_packets(fname):
    # packets = 0
    if not os.path.isfile(fname):
        packets = scapy.utils.rdpcap("vzorky/eth-1.pcap")
    else:
        packets = scapy.utils.rdpcap(fname)
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
    main()
