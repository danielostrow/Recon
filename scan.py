import subprocess
from scapy.all import *
from scapy.layers.inet import TCP, IP
from tqdm import tqdm
import os


def scan():
    print("Scanning...")
    subprocess.call(["arp", "-a"])
    # Store output IPv4 addresses in a list to be used later as a list of strings


def remote_scan():
    target_ip = input("Enter target IP:\t")
    start_port = int(input("Enter start port:\t"))
    end_port = int(input("Enter end port:\t"))

    # Create a TCP SYN packet
    tcp_syn_packet = IP(dst=target_ip) / TCP(flags="S")

    # Loop through the range of ports and send the TCP SYN packet
    open_ports = []
    for port in tqdm(range(start_port, end_port + 1), desc='Scanning ports'):
        # Set the destination port for the TCP SYN packet
        tcp_syn_packet[TCP].dport = port

        # Send the packet and wait for a response
        response = sr1(tcp_syn_packet, timeout=1, verbose=0)

        # Check the response and print the result
        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            open_ports.append(port)

    print(f"Open ports: {open_ports}")


def menu():
    print("1. Scan")
    print("2. Remote Scan")
    print("3. Exit")
    choice = input("Enter choice: ")
    if choice == "1":
        scan()
        menu()
    elif choice == "2":
        remote_scan()
        menu()
    elif choice == "3":
        exit()
    else:
        print("Invalid choice")
        menu()


menu()
