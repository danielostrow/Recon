import subprocess;

subprocess.call(["arp", "-a"]);
subprocess.call(["arp", "-a"], stdout=open('arp.txt', 'w'));

