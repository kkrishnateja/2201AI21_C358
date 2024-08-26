from scapy.all import *
import time

def scapy_ping(destination, count=4):
    print(f"Pinging {destination} with {count} packets:")
    packet = IP(dst=destination)/ICMP()
    
    replies = []
    for i in range(count):
        send_time = time.time()
        reply = sr1(packet, timeout=2, verbose=0)
        recv_time = time.time()
        if reply:
            rtt = (recv_time - send_time) * 1000  # RTT in milliseconds
            print(f"Reply from {reply.src}: bytes={len(reply[ICMP])} time={rtt:.2f}ms TTL={reply.ttl}")
            replies.append(rtt)
        else:
            print("Request timed out.")
    return replies


scapy_ping("8.8.8.8", count=5)
