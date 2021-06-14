import os
from typing import ValuesView
from scapy.all import *

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
        self.ip = get_if_addr(args.interface)
        self.mac = get_if_hwaddr(args.interface)


class ArpScan(Attack):
    def __init__(self, rhosts, iface):
        self.rhosts = rhosts
        super().__init__(iface)

    def __call__(self):
        pass

    @staticmethod
    def get_params():
        return {'RHOSTS': ''}


class ArpPoisoning(Attack):
    def __init__(self, target, gateway, iface):
        self.target = target
        self.gateway = gateway
        super().__init__(iface)

    def __call__(self):
        pass

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': ''}


class SessionHijacking(Attack):
    def __init__(self, target, gateway, iface):
        self.target = target
        self.gateway = gateway
        super().__init__(iface)

    def __call__(self):
        pass

    @staticmethod
    def get_params():
        return {'TARGET': '', 'GATEWAY': ''}


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
                    self.iface
                )

        elif cmd == 'QUIT':
            return True
        
        else:
            # Allow system commands
            print(os.system(cmd))

        return False

def main():
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

if __name__ == '__main__':
    main()