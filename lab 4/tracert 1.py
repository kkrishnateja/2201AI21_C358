from scapy.all import *
import time
import sys
import socket

def custom_tracert(destination, max_ttl=30, packet_size=64, timeout=2, pings_per_hop=1, delay_between_pings=0, source_ip=None, output_file=None):
    # Resolve destination IP address
    try:
        target_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Error: Invalid destination IP or hostname '{destination}'")
        return

    # Validate parameters
    if max_ttl <= 0 or packet_size <= 0 or timeout <= 0 or pings_per_hop <= 0 or delay_between_pings < 0:
        print("Error: TTL, packet size, timeout, pings per hop, and delay must be non-negative and greater than zero.")
        return

    if source_ip:
        try:
            socket.inet_aton(source_ip)  # Validate source IP
        except socket.error:
            print(f"Error: Invalid source IP address '{source_ip}'")
            return

    print(f"Tracing route to {destination} ({target_ip}) with {packet_size} bytes of data:")

    # Open output file if specified
    if output_file:
        try:
            file = open(output_file, 'w')
        except IOError as e:
            print(f"Error: Could not open output file '{output_file}' - {e}")
            return

    # Initialize statistics
    results = []
    for ttl in range(1, max_ttl + 1):
        hop_times = []
        for _ in range(pings_per_hop):
            # Create ICMP packet with specified TTL and packet size
            packet = IP(dst=target_ip, ttl=ttl, src=source_ip)/ICMP()/Raw(load="X" * packet_size)
            send_time = time.time()  # Time when packet is sent
            
            try:
                # Send the packet and wait for the response
                response = sr1(packet, timeout=timeout, verbose=False)
            except Exception as e:
                print(f"Error sending packet: {e}")
                response = None
            
            if response:
                # Calculate RTT
                rtt = (time.time() - send_time) * 1000  # RTT in milliseconds
                hop_times.append(rtt)
                print(f"{ttl:<2}  {response.src:<15}  {rtt:.2f} ms")
            else:
                hop_times.append(None)
                print(f"{ttl:<2}  * * *  Request timed out.")
            
            time.sleep(delay_between_pings)  # Delay between pings
        
        # Calculate statistics for the hop
        if hop_times:
            rtts = [time for time in hop_times if time is not None]
            min_rtt = min(rtts) if rtts else float('inf')
            max_rtt = max(rtts) if rtts else float('inf')
            avg_rtt = sum(rtts) / len(rtts) if rtts else 0
            loss_percentage = (hop_times.count(None) / len(hop_times)) * 100
        else:
            min_rtt = max_rtt = avg_rtt = 0
            loss_percentage = 100
        
        # Append result for the hop
        results.append((ttl, response.src if response else '*', min_rtt, max_rtt, avg_rtt, loss_percentage))

        # Stop if destination is reached
        if response and response.src == target_ip:
            break

    # Print final results
    print("\nTrace complete.")
    print(f"\n{'Hop':<5} {'IP Address':<15} {'Min RTT':<10} {'Max RTT':<10} {'Avg RTT':<10} {'Loss %':<10}")
    for ttl, ip, min_rtt, max_rtt, avg_rtt, loss_percentage in results:
        print(f"{ttl:<5} {ip:<15} {min_rtt:.2f} ms {max_rtt:.2f} ms {avg_rtt:.2f} ms {loss_percentage:.2f} %")
    
    # Write to output file if specified
    if output_file:
        with open(output_file, 'w') as file:
            file.write("Hop\tIP Address\tMin RTT\tMax RTT\tAvg RTT\tLoss %\n")
            for ttl, ip, min_rtt, max_rtt, avg_rtt, loss_percentage in results:
                file.write(f"{ttl}\t{ip}\t{min_rtt:.2f} ms\t{max_rtt:.2f} ms\t{avg_rtt:.2f} ms\t{loss_percentage:.2f} %\n")
        print(f"Results saved to '{output_file}'.")

# Example usage with command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python custom_tracert.py <destination> [max_ttl] [packet_size] [timeout] [pings_per_hop] [delay_between_pings] [source_ip] [output_file]")
        sys.exit(1)

    destination = sys.argv[1]
    max_ttl = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    packet_size = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 2
    pings_per_hop = int(sys.argv[5]) if len(sys.argv) > 5 else 1
    delay_between_pings = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    source_ip = sys.argv[7] if len(sys.argv) > 7 else None
    output_file = sys.argv[8] if len(sys.argv) > 8 else None

    custom_tracert(destination, max_ttl, packet_size, timeout, pings_per_hop, delay_between_pings, source_ip, output_file)
