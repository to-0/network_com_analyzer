# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
#from scapy.all import *
import binascii

import scapy.utils

def main():
    task = input("Enter the number of task:")
    file_name = input("Enter name of the file with .pcap")
    if task == 1:
        analyze(file_name)


def test():
    # Use a breakpoint in the code line below to debug your script.
    #packet = rdpcap("eth-1.pcap")
    # jeden byte su 2 hexadecimalne znaky (1 hex = 4bity 15->1111)
    packets = scapy.utils.rdpcap("eth-1.pcap")
    print(len(bytes(packets[0])))
    for packet in packets:
        for byte in bytes(packet):
            #print(hex(byte))
            return
    #i = int(test[:1],16)

def analyze(fname):
    packets = scapy.utils.rdpcap("eth-1.pcap")
    packet_number  = 1
    for packet in packets:
        #print(packet)
        #print(len(bytes(packets[0])))
        packet = bytes(packet)
        #dlzka1 = len(packet)
        #dlzka2 = len(bytes(packet))
        #print("DLZKA 1 "+str(dlzka1))
        #print("DLZKA 2 " + str(dlzka2))
        s = ""
        counter = 0 ## pocitam kolka bytov som precital
        helper = 0
        mac_source = ""
        mac_dest = ""
        test = packet[0:5]
        typ = ""
        ip_source = ""
        ip_dest = ""
        #print(packet[12:14])
        #print("TEST " + str(test.hex()))
        for i in range(len(packet)):
            #print(packet[i:i+1])
            if counter == 6:
                helper = 1
            if counter == 12:
                helper = 2
            if helper == 0:
                mac_dest += str(packet[i:i + 1].hex())+"."
            if helper == 1:
                mac_source += str(packet[i:i + 1].hex())+"."
            if helper == 2:
                typ = find_type(packet[12:14].hex())
            s += str(packet[i:i+1])+"."
            i += 1
            counter += 1
        #print(packet[26:30])
        ip_source = transform_ip_to_dec(packet[26:30])
        ip_dest = transform_ip_to_dec(packet[30:34])
        print('ramec '+str(packet_number))
        print("Dlzka paketu "+ str(len(packet)))
        print("MAC zdrojova " + mac_source)
        print("MAC cielova " + mac_dest)
        print(typ)
        print("IP cielova: "+ip_dest)
        print("IP zdrojova: "+ip_source)
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
    for line in lines:
        arr = line.split()
        #print(arr)
        if len(arr) > 1:
            hex_val_str = "0x"+hex_val_str
            if hex_val_str == arr[0]:
                return arr[1]
if __name__ == '__main__':
    #test()
    analyze("")


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
