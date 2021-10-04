# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import binascii
import os
import scapy.utils
#import scapy.all as scapy

protocols_dictionary = {}


class DefPacket:
    def __init__(self, mac_source, mac_dest, data, packet_number, length):
        self.mac_source = mac_source
        self.mac_dest = mac_dest
        self.data = data
        self.packet_number = packet_number
        self.ethernet_type =""
        self.length = length
        eth_type_hex = int(data[12:14].hex(), 16)  # zoberiem si nasledujuce 2B po mac adresach
        eth_type = ""
        if eth_type_hex >= int('0x0800', 16):  # ak je to rovne 0800 tak je to cisty ETHERNET II
            self.ethernet_type = "Ethernet II"
            #self.protocol = find_type(data[12:14].hex())
            self.protocol = protocols_dictionary["0x"+data[12:14].hex()]
            self.ip_source = data[26:30]  # ked je to ethernet II tak IP adresy su tu
            self.ip_dest = data[30:34]
        else:  # je to 802.3 ale este musim zistit typ cez dalsie 2 bajty
            nb = int(data[14:16].hex(), 16)
            if nb == int('0xaaaa', 16):
                self.ethernet_type = "Ethernet 802.3 LLC + SNAP"
            elif nb == int('0xffff', 16):
                self.ethernet_type = "802.3 RAW"
            else:
                self.ethernet_type = "IEEE 802.3 LLC"
                #self.protocol = find_type(data[16:17].hex())
                self.protocol = protocols_dictionary["0x" + data[12:14].hex()]

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

    def print_info(self):
        print('ramec ' + str(self.packet_number))
        print("Dlzka ramca " + str(len(self.data)))
        real_length = len(self.data) + 4
        if real_length < 64:
            real_length = 64

        print("Skutocna dlzka ramca " + str(real_length))
        print(self.ethernet_type)
        mac_source_str = ""
        mac_dest_str = ""
        mac_len = int(len(self.mac_source))  # 12 lebo je to v stringu
        for i in range(0, len(self.mac_dest) - 2, 2):
            mac_dest_str += self.mac_dest[i:i + 2] + "."
            mac_source_str += self.mac_source[i:i + 2] + "."
        mac_dest_str += self.mac_dest[mac_len - 2: mac_len]
        mac_source_str += self.mac_source[mac_len - 2: mac_len]
        print("MAC zdrojova " + mac_source_str.upper())
        print("MAC cielova " + mac_dest_str.upper())
        if not self.protocol == "NOT FOUND":
            print(" ".join(self.protocol))
        if self.protocol == "IPv4":
            if not (self.ip_dest == "" or self.ip_source == ""):
                print("IP cielova: " + transform_ip_to_dec(self.ip_dest))
                print("IP zdrojova: " + transform_ip_to_dec(self.ip_source))
                self.protocol_tcp_udp = find_type(self.data[23:24].hex())
                print(self.protocol_tcp_udp)

        self.print_data()



def main():
    load_dictionary()
    task = input("Enter the number of task: ")
    file_name = input("Enter name of the file with .pcap: ")
    packets = load_packets(file_name)
    if int(task) == 1:
        task_1(packets)


def test():
    # Use a breakpoint in the code line below to debug your script.
    #packet = rdpcap("eth-1.pcap")
    # jeden byte su 2 hexadecimalne znaky (1 hex = 4bity 15->1111)

    packets = scapy.utils.rdpcap("vzorky/trace-1.pcap")
    print(packets)
    print(len(bytes(packets[0])))
    for packet in packets:

        print(packet)
    #i = int(test[:1],16)

def task_1(packets):
    for packet in packets:
        packet.print_info()

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
        s = ""
        counter = 0 ## pocitam kolka bytov som precital
        helper = 0
        mac_source = ""
        mac_dest = ""
        typ = ""
        ip_source = ""
        ip_dest = ""
        typ = find_type(packet[12:14].hex())
        # #ZISTOVANIE TYPU ETHERNET RAMCA
        # eth_type_hex = int(packet[12:14].hex(), 16) #zoberiem si nasledujuce 2B po mac adresach
        # print("TEST" + str(packet[12:14]))
        # print(type(packet[0:6]))
        # eth_type = ""
        # if eth_type_hex >= int('0x0800', 16): #ak je to rovne 0800 tak je to cisty ETHERNET II
        #     eth_type = "Ethernet II"
        #     ip_source = packet[26:30] #ked je to ethernet II tak IP adresy su tu
        #     ip_dest = packet[30:34]
        #     my_packet_list.append(MyPacket(packet[0:6].hex(), packet[6:12].hex(), packet[26:30], packet[30:34], typ,
        #                                    packet, packet_number, len(packet), eth_type, protocol_type))
        # else: #je to 802.3 ale este musim zistit typ cez dalsie 2 bajty
        #     nb = int(packet[14:16].hex(), 16)
        #     if nb == int('0xaaaa', 16):
        #         eth_type = "Ethernet 802.3 LLC + SNAP"
        #     elif nb == int('0xffff', 16):
        #         eth_type = "802.3 RAW"
        #     else:
        #         eth_type = "IEEE 802.3 LLC"
        #         protocol = find_type(packet[16:18].hex())
        #
        my_packet_list.append(DefPacket(packet[0:6].hex(), packet[6:12].hex(), packet, packet_number, len(packet)))
        #my_packet_list[packet_number-1].print_info()
        packet_number += 1
        print("-"*50)
    return my_packet_list

# Press the green button in the gutter to run the script.
def transform_ip_to_dec(ip):
    res = ""
    for byte in ip:
        res += str(byte) + "."
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


def find_type(hex_val_str):
    #print(hex_val_str)
    global protocols_dictionary
    global protocols
    if not protocols:
        f = open("hodnoty")
        protocols = f.readlines()
    hex_val_str = "0x" + hex_val_str
    counter = 0
    for line in protocols:
        arr = line.split()
        #print(arr)
        if arr[0][0] != "#":
            if hex_val_str == arr[0]:
                if counter == 3:
                    return arr[1] + " " +arr[2]
                return arr[1]
        else:
            counter += 1
    return "NOT FOUND"

if __name__ == '__main__':
    #test()
    #analyze("")
    main()


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
