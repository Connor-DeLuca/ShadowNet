from scapy.all import sniff, ARP, DNS, IP

arp_table = {}  # Keeps track of IP -> MAC

def load_suspicious_domains():
    with open("suspicious_domains.txt", "r") as f:
        return set(line.strip().lower() for line in f if line.strip())

suspicious_domains = load_suspicious_domains()

def is_suspicious(domain):
    domain = domain.lower()
    for bad in suspicious_domains:
        if bad in domain:
            return True
    return False

def process_packet(packet):
    try:
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qd is not None:  # Check if there is a question section
                try:
                    dns_query = dns_layer.qd.qname.decode(errors="ignore").strip(".")
                    ip_src = packet[IP].src if packet.haslayer(IP) else "Unknown IP"
                    if is_suspicious(dns_query):
                        print(f"[⚠️  WARNING] {ip_src} -> Suspicious DNS Query: {dns_query}")
                except Exception as e:
                    pass # Ignore errors in DNS parsing

        elif packet.haslayer(ARP):
            arp_ip = packet[ARP].psrc
            arp_mac = packet[ARP].hwsrc

            if arp_ip not in arp_table:
                arp_table[arp_ip] = arp_mac
            else:
                if arp_table[arp_ip] != arp_mac:
                    print(f"[⚠️  ARP SPOOFING WARNING] IP {arp_ip} changed from {arp_table[arp_ip]} to {arp_mac}")
                    arp_table[arp_ip] = arp_mac  # Update to new MAC after warning

        # We can add other protocol handlers here

    except Exception:
        pass  # Silence parse errors for smooth running

def start_sniffing(interface):
    print(f"[*] Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=process_packet, store=False)
