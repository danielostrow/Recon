import subprocess
from scapy.all import *
from scapy.layers.inet import TCP, IP
from tqdm import tqdm
import os


def scan():
    print("Scanning...")
    subprocess.call(["arp", "-a"])
    # Store output IPv4 addresses in a list to be used later as a list of strings


def grab_banner(target_ip, port):
    try:
        # Create a TCP SYN packet
        tcp_syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send the SYN packet and wait for a response
        response = sr1(tcp_syn_packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            # Send an additional request to grab the banner
            tcp_request = IP(dst=target_ip) / TCP(dport=port, flags="A")
            response = sr1(tcp_request, timeout=1, verbose=0)

            if response and response.haslayer(TCP) and response[TCP].payload:
                banner = response[TCP].payload.load.decode('utf-8', errors='ignore')
                return banner.strip()
    except Exception as e:
        pass

    return None


def remote_scan():
    target_ip = input("Enter target IP:\t")
    start_port = int(input("Enter start port:\t"))
    end_port = int(input("Enter end port:\t"))

    # Create a TCP SYN packet
    tcp_syn_packet = IP(dst=target_ip) / TCP(flags="S")

    # Initialize an empty list to store open ports and banners
    open_ports_and_banners = []

    for port in tqdm(range(start_port, end_port + 1), desc='Scanning ports'):
        tcp_syn_packet[TCP].dport = port

        # Send the packet and wait for a response
        response = sr1(tcp_syn_packet, timeout=1, verbose=0)

        # Check the response and add open ports and banners to the list
        if response and response.haslayer(TCP) and response[TCP].flags == "SA":
            # Banner grabbing
            banner = grab_banner(target_ip, port)
            open_ports_and_banners.append((port, banner))

    if not open_ports_and_banners:
        print("No open ports found.")
    else:
        print("Open ports and banners:")
        for port, banner in open_ports_and_banners:
            print(f"{port}:\n{banner}")


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
