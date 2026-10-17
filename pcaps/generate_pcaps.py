import time
import scapy.config
scapy.config.conf.sniff_promisc = 0
scapy.config.conf.use_pcap = True
from scapy.all import IP, TCP, wrpcap, Ether, UDP

def generate_benign():
    packets = []
    base_time = time.time()
    
    # TCP Handshake + HTTP GET
    eth = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    ip = IP(src="10.0.0.1", dst="10.0.0.2")
    
    syn = eth / ip / TCP(sport=50000, dport=80, flags="S", seq=100)
    syn.time = base_time
    packets.append(syn)
    
    synack = eth / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=50000, flags="SA", seq=200, ack=101)
    synack.time = base_time + 0.01
    packets.append(synack)
    
    ack = eth / ip / TCP(sport=50000, dport=80, flags="A", seq=101, ack=201)
    ack.time = base_time + 0.02
    packets.append(ack)
    
    req = eth / ip / TCP(sport=50000, dport=80, flags="PA", seq=101, ack=201) / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    req.time = base_time + 0.03
    packets.append(req)
    
    wrpcap("pcaps/benign_sample.pcap", packets)

def generate_portscan():
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.100"
    
    eth = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    
    # Host 1: 15 distinct ports
    dst1 = "10.0.0.10"
    for i in range(15):
        pkt = eth / IP(src=src_ip, dst=dst1) / TCP(sport=50000+i, dport=1001+i, flags="S")
        pkt.time = base_time + (i * 0.01)
        packets.append(pkt)
    
    # Hosts 2-5: 1 distinct port each
    current_time = base_time + 0.2
    for i, dst in enumerate(["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"]):
        pkt = eth / IP(src=src_ip, dst=dst) / TCP(sport=60000+i, dport=1016+i, flags="S")
        pkt.time = current_time + (i * 0.01)
        packets.append(pkt)
        
    wrpcap("pcaps/portscan_sample.pcap", packets)

def generate_multistage():
    packets = []
    base_time = time.time()
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.20"
    eth = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    
    # Phase 1: Port scan against single host (15 ports)
    for i in range(15):
        pkt = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000+i, dport=1+i, flags="S")
        pkt.time = base_time + (i * 0.01)
        packets.append(pkt)
        
    # Phase 2: Malicious payload (SQLi)
    # Wait 2 seconds
    mal_time = base_time + 2.0
    syn = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=51000, dport=80, flags="S", seq=100)
    syn.time = mal_time
    packets.append(syn)
    
    req = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=51000, dport=80, flags="PA", seq=101, ack=201) / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nunion select * from users--"
    req.time = mal_time + 0.02
    packets.append(req)

    wrpcap("pcaps/multistage_sample.pcap", packets)

def generate_distributed_target():
    packets = []
    base_time = time.time()
    dst_ip = "10.0.0.30"
    eth = Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    
    src_ips = ["192.168.1.201", "192.168.1.202", "192.168.1.203"]
    
    for i, src_ip in enumerate(src_ips):
        mal_time = base_time + (i * 0.5)
        syn = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000+i, dport=80, flags="S", seq=100)
        syn.time = mal_time
        packets.append(syn)
        
        req = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000+i, dport=80, flags="PA", seq=101, ack=201) / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nunion select * from admin--"
        req.time = mal_time + 0.02
        packets.append(req)

    wrpcap("pcaps/distributed_target_sample.pcap", packets)

if __name__ == "__main__":
    import os
    if not os.path.exists("pcaps"):
        os.makedirs("pcaps")
    generate_benign()
    generate_portscan()
    generate_multistage()
    generate_distributed_target()
    print("Generated 4 PCAPs successfully.")
