from scapy.all import IP, ICMP, sr1, Raw  
import time

def scapy_traceroute(destination, max_ttl=30, timeout=2):
    for ttl in range(1, max_ttl + 1):
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        reply = sr1(packet, timeout=timeout, verbose=0)
        if reply:
            print(f"{ttl}\t{reply.src}\t{reply.time * 1000:.2f} ms")
            if reply.type == 0:  # ICMP Echo Reply
                break
        else:
            print(f"{ttl}\t*\tRequest timed out.")

scapy_traceroute("8.8.8.8", max_ttl=20)
