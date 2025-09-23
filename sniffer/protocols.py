def parse_ethernet_frame(packet):
    # parses the Ethernet frame from the packet.
    dest_mac = packet.dst
    src_mac = packet.src
    return f"[+] Ethernet Frame: {src_mac} -> {dest_mac}"


def parse_ip_packet(ip_packet):
    # parses the IP packet header.
    # returns string and protocol type
    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    protocol = protocol_map.get(ip_packet.proto, str(ip_packet.proto))

    info_string = (
        f"\t[+] IP Packet (Proto: {protocol})\n"
        f"\t[+] Source IP: {ip_packet.src}\n"
        f"\t[+] Destination IP: {ip_packet.dst}\n"
    )
    return info_string, protocol


def parse_tcp_segment(tcp_segment):
    # parses the tcp segment, returns a formatted string and the payload data
    info_string = (
        f"\t\t[+] TCP Segment\n"
        f"\t\t\t- Source Port: {tcp_segment.sport}\n"
        f"\t\t\t- Destination Port: {tcp_segment.dport}"
    )
    payload = bytes(tcp_segment.payload)
    return info_string, payload


def parse_udp_datagram(udp_datagram):
    # parses the udp datagram, returns a formatted string and the payload data
    info_string = (
        f"\t\t[+] UDP Datagram\n"
        f"\t\t\t- Source Port: {udp_datagram.sport}\n"
        f"\t\t\t- Destination Port: {udp_datagram.dport}"
    )
    payload = bytes(udp_datagram.payload)
    return info_string, payload
