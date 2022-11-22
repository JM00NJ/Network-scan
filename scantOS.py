import os
import socket
import sys
import time
import random
import urllib.request
import scapy.layers.inet
from scapy.layers.inet import TCP, ICMP
from scapy.layers.l2 import arping
from IPy import IP
from colorama import Fore
from scapy.all import load_module
from scapy.config import conf
from scapy.modules.nmap import nmap_fp
from scapy.sendrecv import sr1, sr


def reverseName(ip):
    if ip[0] == "w":
        ip = socket.gethostbyname(ip)
        t = IP(ip)
        print(Fore.BLUE + "reverse:\n" + t.reverseName())
        print(Fore.BLUE + "ip_type:\n" + t.iptype())
    else:
        t = IP(ip)
        print(Fore.BLUE + "reverse:\n" + t.reverseName())
        print(Fore.BLUE + "ip_type:\n" + t.iptype())


def host_fingerprint(t,port):

    path = os.getcwd()
    scan = os.scandir(path)
    print(Fore.GREEN + "Scanning current dir files for nmap-os-fingerprints[file] | path:: %s" %path)
    for files in scan:
        if files.name.startswith("nmap-os-fingerprints"):
            print(Fore.GREEN + "nmap-os-fingerprints file have")
            break
        else:
            print(Fore.GREEN + "Dont have nmap-os-fingerprints file gonna download...")
            open('nmap-os-fingerprints', 'wb').write(
                    urllib.request.urlopen('https://raw.githubusercontent.com/nmap/nmap/9efe1892/nmap-os-fingerprints').read())
    load_module("nmap")
    conf.nmap_base = "nmap-os-fingerprints"
    fpr = nmap_fp(t,oport=port,cport=1)
    print(fpr)

def host_discovery(range):
    gw = conf.route.route("0.0.0.0")[2]
    print(Fore.GREEN + "Gateway :: ", gw)
    gw = gw+range
    send_arp = arping(gw,timeout=4,verbose=True)
def portscan():
    host = str(input("Target host to scan:"))
    start = int(input("Start-port {range}>>"))
    end = int(input("End-port {range}>>"))
    for p in range(start,end+1):
        src_p = random.randint(1025,65534)
        packet = sr1(scapy.layers.inet.IP(dst=host) / TCP(sport=src_p, dport=p, flags="S"), timeout=1,verbose=0)
        if packet is None:
            print(f"{host}:{p} is filtered")
        elif packet.haslayer(TCP):
            if packet.getlayer(TCP).flags == 0x12:
                sr(scapy.layers.inet.IP(dst=host) / TCP(sport=src_p, dport=p, flags='R'), timeout=1, verbose=0)
                print(f"{host}:{p} is open")
            elif packet.getlayer(TCP).flags == 0x14:
                pass
            elif packet.haslayer(TCP):
                if int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"{host}:{p} is filtered")


os.system("clear")
print("Network tools")
while True:
    try:
        print(Fore.CYAN + "\nReverse DNS Lookup:(1)")
        print(Fore.CYAN + "Host Fingerprint Guess(2)")
        print(Fore.CYAN + "Host discovery On Local Network(3)")
        print(Fore.CYAN + "Port Scan [SYN](4)")

        choose = int(input(Fore.RED + "\nChoose the Tool :: "))
        if choose > 4 or choose < 1:
            print("Input is not valid number!!!")
            pass
        elif choose == 1:
            ip = input(Fore.RED + "IP addr to reverse dns look-up => ")
            reverseName(ip)
        elif choose == 2:
            t = input(Fore.RED + "Target addr to scan fingerprint => ")
            if t[1] == "w":
                t = socket.gethostbyname(t)
                print(Fore.BLUE + t)
            else:
                print(Fore.GREEN + t)
            port = int(input(Fore.RED + "Target scan port => "))
            port = str(port)
            print(Fore.GREEN + port)
            port = int(port)
            host_fingerprint(t,port)
        elif choose == 3:
            rge = str(input("range; example: /16 - /24 => "))
            try:
                if rge[0] != "/":
                    print(Fore.RED + "missing {/}")
                elif int(rge[1:3]) > 32:
                    print("cant more than (32)")
                else:
                    host_discovery(rge)

            except KeyboardInterrupt:
                print(Fore.RED + "Quit")
                sys.exit()
        elif choose == 4:
            print(Fore.GREEN + "#############\nSYN SCAN\n#############\nClosed Ports Wont Show Up\n")
            portscan()
            print("Scan is Done")

    except ValueError:
        print("Empty input entered")
    except KeyboardInterrupt:
        print(Fore.RED + "\nQuit")
        time.sleep(2)
        os.system("clear")
        sys.exit()