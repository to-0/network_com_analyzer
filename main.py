# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
#from scapy.all import *
import binascii
import os

import scapy.utils


class MyPacket:
    def __init__(self, mac_source, mac_dest, ip_source, ip_dest, type_p, data, packet_number, length, ethernet_type,
                 ip_protocol_type):
        self.mac_source = mac_source
        self.mac_dest = mac_dest
        self.ip_source = ip_source
        self.ip_dest = ip_dest
        self.type_p = type_p
        self.data = data
        self.packet_number = packet_number
        self.length = length
        self.ethernet_type = ethernet_type
        self.ip_protocol = ip_protocol_type

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
        print("Skutocna dlzka ramca "+str(len(self.data)+4))
        print(self.ethernet_type)
        mac_source_str = ""
        mac_dest_str = ""
        print(type(self.mac_source))
        mac_len = int(len(self.mac_source)) #12 lebo je to v stringu
        for i in range(0, len(self.mac_dest)-2, 2):
            mac_dest_str += self.mac_dest[i:i+2]+"."
            mac_source_str += self.mac_source[i:i+2]+"."
        mac_dest_str += self.mac_dest[mac_len-2: mac_len]
        mac_source_str += self.mac_source[mac_len - 2: mac_len]
        print("MAC zdrojova " + mac_source_str.upper())
        print("MAC cielova " + mac_dest_str.upper())
        print(self.type_p)
        print("IP cielova: " + transform_ip_to_dec(self.ip_dest))
        print("IP zdrojova: " + transform_ip_to_dec(self.ip_source))
        print(self.ip_protocol)
        self.print_data()



def main():
    task = input("Enter the number of task: ")
    file_name = input("Enter name of the file with .pcap: ")
    if int(task) == 1:
        analyze(file_name)


def test():
    # Use a breakpoint in the code line below to debug your script.
    #packet = rdpcap("eth-1.pcap")
    # jeden byte su 2 hexadecimalne znaky (1 hex = 4bity 15->1111)

    packets = scapy.utils.rdpcap("vzorky/trace-1.pcap")
    print(packets)
    print(len(bytes(packets[0])))
    for packet in packets:
        packet = bytes(packet)
        t = packet[0:6]
        for i in t:
            print(i)
        return
    #i = int(test[:1],16)

def analyze(fname):
    packets = 0
    if fname == "":
        packets = scapy.utils.rdpcap("vzorky/trace-1.pcap")
    if not os.path.isfile("vzorky/" + fname):
        packets = scapy.utils.rdpcap("vzorky\eth-1.pcap")
    else:
        packets = scapy.utils.rdpcap("vzorky/"+ fname)
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
        #print(packet[12:14])
        #print("TEST " + str(test.hex()))
        # for i in range(len(packet)):
        #     #print(packet[i:i+1])
        #     if counter == 6:
        #         helper = 1
        #     if counter == 12:
        #         helper = 2
        #     if helper == 0:
        #         mac_dest += str(packet[i:i + 1].hex())+"."
        #     if helper == 1:
        #         mac_source += str(packet[i:i + 1].hex())+"."
        #     if helper == 2:
        #         typ = find_type(packet[12:14].hex())
        #     s += str(packet[i:i+1])+"."
        #     i += 1
        #     counter += 1
        #print(packet[26:30])
        typ = find_type(packet[12:14].hex())
        protocol_type = find_type(packet[23:24].hex())
        ip_source = transform_ip_to_dec(packet[26:30])
        ip_dest = transform_ip_to_dec(packet[30:34])
        # print('ramec '+str(packet_number))
        # print("Dlzka paketu "+ str(len(packet)))
        # print("MAC zdrojova " + mac_source)
        # print("MAC cielova " + mac_dest)
        # print(typ)
        # print("IP cielova: "+ip_dest)
        # print("IP zdrojova: "+ip_source)

        #ZISTOVANIE TYPU ETHERNET RAMCA
        eth_type_hex = int(packet[12:14].hex(), 16) #zoberiem si nasledujuce 2B po mac adresach
        print("TEST")
        print(type(packet[0:6]))
        eth_type = ""
        if eth_type_hex >= int('0x0800', 16): #ak je to rovne 0800 tak je to cisty ETHERNET II
            eth_type = "Ethernet II"
        else: #je to 802.3 ale este musim zistit typ cez dalsie 2 bajty
            nb = int(packet[14:16].hex(), 16)
            if nb == int('0xaaaa', 16):
                eth_type = "Ethernet 802.3 LLC + SNAP"
            elif nb == int('0xffff', 16):
                eth_type = "802.3 RAW"
            else:
                eth_type = "IEEE 802.3 LLC"
        my_packet_list.append(MyPacket(packet[0:6].hex(), packet[6:12].hex(), packet[26:30], packet[30:34], typ,
                             packet, packet_number, len(packet), eth_type, protocol_type))
        my_packet_list[packet_number-1].print_info()
        packet_number += 1
        print("")

# Press the green button in the gutter to run the script.
def transform_ip_to_dec(ip):
    res = ""
    for byte in ip:
        res += str(byte) + "."
    return res

def find_type(hex_val_str):
    #print(hex_val_str)
    f = open("hodnoty")
    lines = f.readlines()
    hex_val_str = "0x" + hex_val_str
    counter = 0
    for line in lines:
        arr = line.split()
        #print(arr)
        if arr[0][0] != "#":
            if hex_val_str == arr[0]:
                f.close()
                if counter == 3:
                    return arr[2]
                return arr[1]
        else:
            counter += 1

    f.close()
    return "NOT FOUND"

if __name__ == '__main__':
    #test()
    #analyze("")
    main()


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
