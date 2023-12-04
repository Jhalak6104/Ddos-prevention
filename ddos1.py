
from scapy.all import sniff, IP , TCP , Raw , wrpcap
import subprocess
import time


def drop_packets_temporarily():
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-j', 'DROP'])
        print("Incoming packets dropped successfully.")
        time.sleep(3600)
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-j', 'DROP'])
        print(f"Incoming packets allowed after {3600} seconds.")
    except subprocess.CalledProcessError as e:
        print(f"Error dropping/allowing incoming packets: {e}")


def block_ip_temporarily(ip_address):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        print(f"IP {ip_address} blocked successfully.")  
        time.sleep(3600)
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        print(f"IP {ip_address} unblocked after {3600} seconds.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking/unblocking IP {ip_address}: {e}")


def block_ip(ip_address):
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        print(f"IP {ip_address} blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")



#incomplete_conn_count = {}
def incomplete_syn():
    sniff(prn=packet_callback_for_syn, store=0, filter="tcp",iface = "wlan0")
def packet_callback_for_syn(packet):
    incomplete_conn_count = {}
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        flags = packet[TCP].flags
        if flags & 0x02 and not flags & 0x10:
            # Update count for incomplete connection request
            incomplete_conn_count[src_ip] = incomplete_conn_count.get(src_ip, 0) + 1
            # Check if the count exceeds the threshold (e.g., 100)
            if len(incomplete_conn_count) > 2000:
                print("Alert : more than 2000 incomplete syn request detected")
                drop_packets_temporarily()
            if incomplete_conn_count[src_ip] > 100:
                print(f"Alert: More than 100 incoming incomplete connection requests from {src_ip}")
                block_ip_temporarily(src_ip)



#incomplete_get_count = {}
def incomplete_get():
    sniff(prn=packet_callback_for_get, store=0, filter="tcp port 80",iface = "wlan0") 
def packet_callback_for_get(packet):
    incomplete_get_count = {}
    if IP in packet and TCP in packet and Raw in packet:
        src_ip = packet[IP].src
        flags = packet[TCP].flags
        payload = packet[Raw].load.decode('utf-8', 'ignore')

        # Check if the packet is part of an incomplete GET request
        if flags & 0x08 and 'GET' in payload:
            # Update count for incomplete GET request
            incomplete_get_count[src_ip] = incomplete_get_count.get(src_ip, 0) + 1
            if len(incomplete_get_count) > 2000:
                print("Alert : more than 2000 incomplete get request detected")
                drop_packets_temporarily()
            if incomplete_get_count[src_ip] > 100:
                print(f"Alert: More than 100 incoming incomplete GET requests from {src_ip}")
                block_ip_temporarily((src_ip))




def packet_callback(packet):
    packet_count_per_minute ={}
    packet_count_per_ip ={}
    # Check if the packet is an IP packet
    if IP in packet:
        timestamp = int(time.time())
        minute_key = timestamp//60
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        if not (src_ip.startswith('127.')): #or dst_ip.startswith('127.')):
            packet_count_per_ip[src_ip]= packet_count_per_ip.get(src_ip,0) +1
            print(f"Packet recieve from {src_ip}")
            with open("ipadress.txt","a") as f:
                f.write(f"packet recieve from {src_ip}")
                f.write("\n")
            packet_count_per_minute[minute_key] = packet_count_per_minute.get(minute_key, 0) + 1
            if (packet_count_per_minute[minute_key] > 100) :
                if packet_count_per_ip[src_ip] > 100:
                    block_ip_temporarily(src_ip)
                else:
                    incomplete_syn()
                    incomplete_get()
sniff(prn=packet_callback, store=0, timeout=60 , filter="inbound and not src host 127.0.0.1")

