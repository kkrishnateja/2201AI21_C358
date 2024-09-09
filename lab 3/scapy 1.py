from scapy.all import ICMP,IP,sr1,Raw
import time
import sys
import socket

def custom_ping(destination, count=4, ttl=64, packet_size=64, timeout=2):
    try:
        target_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Error: Invalid destination IP or hostname '{destination}'")
        return
    
    if count <= 0 or ttl <= 0 or packet_size <= 0 or timeout <= 0:
        print("Error: Count, TTL, packet size, and timeout must be greater than zero.")
        return
    
    print(f"Pinging {destination} ({target_ip}) with {packet_size} bytes of data:")

    sent_packets = 0
    received_packets = 0
    rtts = []

    for i in range(count):
        packet = IP(dst=target_ip, ttl=ttl)/ICMP()/Raw(load="X" * packet_size)
        send_time = time.time()  

        try:
            response = sr1(packet, timeout=timeout, verbose=False)
        except Exception as e:
            print(f"Error sending packet: {e}")
            continue
        
        sent_packets += 1
        
        if response:
            rtt = (time.time() - send_time) * 1000  
            rtts.append(rtt)
            received_packets += 1
            print(f"Reply from {response.src}: bytes={packet_size} time={rtt:.2f}ms TTL={response.ttl}")
        else:
            print("Request timed out.")
    
    loss_percentage = ((sent_packets - received_packets) / sent_packets) * 100
    avg_rtt = sum(rtts) / len(rtts) if rtts else 0
    min_rtt = min(rtts) if rtts else 0
    max_rtt = max(rtts) if rtts else 0
    
    print("\nPing statistics for {}: ".format(destination))
    print(f"    Packets: Sent = {sent_packets}, Received = {received_packets}, Lost = {sent_packets - received_packets} ({loss_percentage:.2f}% loss)")
    
    if rtts:
        print("Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min_rtt:.2f}ms, Maximum = {max_rtt:.2f}ms, Average = {avg_rtt:.2f}ms")
    else:
        print("No round trip time could be calculated.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python custom_ping.py <destination> [count] [ttl] [packet_size] [timeout]")
        sys.exit(1)
    
    destination = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    ttl = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    packet_size = int(sys.argv[4]) if len(sys.argv) > 4 else 64
    timeout = int(sys.argv[5]) if len(sys.argv) > 5 else 2
    
    custom_ping(destination, count, ttl, packet_size, timeout)
