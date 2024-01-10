import logging
import socket
from scapy.all import *

conf.verb = 0  # disables scapy default verbose mode
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # disables 'No route found for IPv6 destination' warning

t_wait = 1.0  # timeout for the answer to each packet
openPorts = [] 
closedPorts = [] 
filteredPorts = []
opfilPorts = [] 

#############################################################################
# ICMP Codes (Type 3) Used to determine filtering:                          #
# 1  Host Unreachable                                                       #
# 2  Protocol Unreachable                                                   #
# 3  Port Unreachable                                                       #
# 9  Communication with Destination Network is Administratively Prohibited  #
# 10  Communication with Destination Host is Administratively Prohibited    #
# 13  Communication Administratively Prohibited                             #
#############################################################################

def banner_grabber(target, port):
    try:
        # Cria um socket TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)

        # Conecta ao host na porta especificada
        s.connect((target, port))

        # Recebe os primeiros 1024 bytes da resposta como banner
        banner = s.recv(1024)

        # Fecha a conexão
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
    print("Scanning ports...")
    for port in range(bP, eP + 1):

        #----loading----#
        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()
        #----loading----#

        # envio de pacote usando protocolo
        answer = sr1(IP(dst=tgt) / TCP(dport=port, flags="S"), timeout=t_wait) # explicação sobre as camadas

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

def xmas_scan(tgt, bP, eP):
    print("Scanning ports...")
    for port in range(bP, eP + 1):

        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()

        answer = sr1(IP(dst=tgt) / TCP(sport=bP, dport=eP, flags="FPU"), timeout=t_wait) # explicação 
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
                    get_service_banner(tgt, port)

    summary()


def fin_scan(tgt, bP, eP):
    print("Scanning ports...")

    for port in range(bP, eP + 1):

        #----loading----#
        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()
        #----loading----#

        answer = sr1(IP(dst=tgt) / TCP(sport=bP, dport=eP, flags="F"), timeout=t_wait) #explicação/ pq espera um RST se ele manda um fin
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


def null_scan(tgt, bP, eP):
    print("Scanning ports...")

    for port in range(bP, eP + 1):

        #----loading----#
        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()
        #----loading----#

        answer = sr1(IP(dst=tgt) / TCP(sport=bP, dport=eP, flags=""), timeout=t_wait) # explicação/ quais possíveis respostas ao enviar um pacote TCP sem flag
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
    print("Scanning ports...")

    for port in range(bP, eP + 1):

        #----loading----#
        animation = "|/-\\"
        idx = port % len(animation)
        print("\rChecking port {}: {}".format(port, animation[idx]), end="")
        sys.stdout.flush()
        #----loading----#

        answer = sr1(IP(dst=tgt) / TCP(sport=bP, dport=eP, flags="A"), timeout=t_wait) # explicação / o que acontece se enviar um syn sem resposta
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
                 2: xmas_scan,
                 3: fin_scan,
                 4: null_scan,
                 5: ack_scan,
                 }

    scanModes[mode](tgt, bP, eP)
