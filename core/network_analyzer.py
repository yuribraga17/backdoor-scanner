from scapy.all import sniff

def analyze_network_traffic():
    """
    Analisa o tráfego de rede em busca de atividades suspeitas.
    """
    def packet_callback(packet):
        if packet.haslayer("TCP"):
            print(f"TCP Packet: {packet['TCP'].summary()}")

    sniff(prn=packet_callback, count=10)