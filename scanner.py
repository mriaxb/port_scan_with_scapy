import logging
import socket
import sys
import time
from scapy.all import *

conf.verb = 0 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 

t_wait = 4.0  
openPorts = [] 
closedPorts = [] 
filteredPorts = []
opfilPorts = [] 


def banner_grabber(target, port):
    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)

        s.connect((target, port))

        banner = s.recv(1024)

        s.close()

        return banner.decode('utf-8')

    except Exception as e:
        return f"Error: {str(e)}"

def get_service_banner(target, port):
    try:
        service = socket.getservbyport(port)
        banner = banner_grabber(target, port)
        print(f"Port {port} - Open || Service: {service} || Banner: {banner}")

    except (socket.error, OSError):
        print(f"Port {port} - Open || Service: Unknown || Banner: Not Available")

def syn_scan(tgt, bP, eP):
    print_ascii_art()
    print("Scanning ports...")
    for port in range(bP, eP + 1):

        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()
 
        answer = sr1(IP(dst=tgt) / TCP(dport=port, flags="S"), timeout=t_wait)

        if str(type(answer)) == "<class 'NoneType'>":
            filteredPorts.append(int(port))
            print("\nPort %d - Filtered" % port)
        elif answer.haslayer(TCP):
            if answer.getlayer(TCP).flags == 0x12:
                send_rst = sr(IP(dst=tgt) / TCP(dport=port, flags="R"), timeout=t_wait)
                openPorts.append(int(port))
                get_service_banner(tgt, port)
                # print(f"Port {port} - Open || Service: {get_service_from_packet(answer)}")
            elif answer.getlayer(TCP).flags == 0x14:
                closedPorts.append(int(port))
                # print("Port %d - Closed" % port)
            elif answer.haslayer(ICMP):
                if int(answer.getlayer(ICMP).type) == 3 and int(answer.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    filteredPorts.append(int(port))
                    print("\nPort %d - Filtered" % port)

    print("\nScan complete!")
    summary()

def fin_scan(tgt, bP, eP):
    print_ascii_art()
    print("Scanning ports...")

    for port in range(bP, eP + 1):

        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()

        answer = sr1(IP(dst=tgt) / TCP(sport=bP, dport=eP, flags="F"), timeout=t_wait) 
        if str(type(answer)) == "<class 'NoneType'>":
            opfilPorts.append(int(port))
            print("Port %d - Open/Filtered" % port)

        elif answer.haslayer(TCP):
            if answer.getlayer(TCP).flags == 0x14:
                closedPorts.append(int(port))
                # print("Port %d - Closed" % port)
            elif answer.haslayer(ICMP):
                if int(answer.getlayer(ICMP).type) == 3 and int(answer.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    filteredPorts.append(int(port))
                    print("Port %d - Filtered" % port)
    summary()


def ack_scan(tgt, bP, eP):
    print_ascii_art()
    print("Scanning ports...")

    for port in range(bP, eP + 1):

        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()

        answer = sr1(IP(dst=tgt) / TCP(sport=bP, dport=eP, flags="A"), timeout=t_wait) 
        if str(type(answer)) == "<class 'NoneType'>":
            filteredPorts.append(int(port))
            print("Port %d - Filtered by Stateful Firewall" % port)
        elif answer.haslayer(TCP):
            if answer.getlayer(TCP).flags == 0x14:
                print("Port %d - Unfiltered by Firewall" % port)
            elif answer.haslayer(ICMP):
                if int(answer.getlayer(ICMP).type) == 3 and int(answer.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    filteredPorts.append(int(port))
                    print("Port %d - Filtered by Stateful Firewall" % port)
    summary()


def summary():
    print("============================================================================================")
    print("There are [{0}] open ports, [{1}] filtered ports, [{2}] open/filtered ports, and [{3}] closed ports".format(
        len(openPorts), len(filteredPorts), len(opfilPorts), len(closedPorts)))
    print("The following ports are open:")
    for port in openPorts:
        print("[+] Port %d " % port)
    print("The following ports are filtered:")
    for port in filteredPorts:
        print("[+] Port %d " % port)
    print("============================================================================================")
    


def scan(tgt, bP, eP, mode):
    scanModes = {1: syn_scan,
                 2: fin_scan,
                 3: ack_scan,
                }

    scanModes[mode](tgt, bP, eP)


def print_ascii_art():
    ascii_art = """
        (       )  (             (                   )  
        )\ ) ( /(  )\ )       )   )\ )  (    (     ( /(  
        (()/( )\())(()/(` )  /(  (()/(  )\   )\    )\()) 
        /(_)|(_)\  /(_))( )(_))  /(_)|((_|(((_)( ((_)\  
        (_))   ((_)(_)) (_(_())  (_)) )\___)\ _ )\ _((_) 
        | _ \ / _ \| _ \|_   _|  / __((/ __(_)_\(_) \| | 
        |  _/| (_) |   /  | |    \__ \| (__ / _ \ | .` | 
        |_|   \___/|_|_\  |_|    |___/ \___/_/ \_\|_|\_| 
                                
    """
    red_text = "\033[91m"

    yellow_text = "\033[93m"
    reset_color = "\033[0m"

    for char in ascii_art:
        if char in ['_','|','/', '9']:
            print(red_text + char, end='', flush=True)
        else:
            print(yellow_text + char, end='', flush=True)
        time.sleep(0.004) 

    print(reset_color)