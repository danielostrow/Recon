import subprocess

def scan():
    print("Scanning...")
subprocess.call(["arp", "-a"])
subprocess.call(["arp", "-a"])

def menu():
    print("1. Scan")
    print("2. Exit")
    choice = input("Enter choice: ")
    if choice == "1":
        scan()
    elif choice == "2":
        exit()
    else:
        print("Invalid choice")
        menu()
