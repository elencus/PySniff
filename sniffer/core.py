from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from .protocols import *
from .utils import *


def packet_callback(packet, writer=None):
    # the main func called for each captured packet
    # it orchestrates the parsing of different layers
    # optionally writes to a pcap file

    if writer:
        writer.write(packet)
    print("\n" + "=" * 60)

    eth_info = parse_ethernet_frame(packet)
    print(eth_info)

    # check if the packet has an IP layer
    if IP in packet:
        ip_info, proto = parse_ip_packet(packet[IP])
        print(ip_info)

        if proto == "TCP" and TCP in packet:
            tcp_info, payload = parse_tcp_segment(packet[TCP])
            print(tcp_info)
            if payload:
                print(format_payload_data(payload))


        elif proto == "UDP" and UDP in packet:
            udp_info, payload = parse_udp_datagram(packet[UDP])
            print(udp_info)
            if payload:
                print(format_payload_data(payload))


        elif proto == "ICMP" and ICMP in packet:
            print("\t\t[+] ICMP packet")

    print("=" * 60)


def start_sniffing(interface, count=0, timeout=0, save_file=None):
    # starts the sniffing process on a given interface
    # param interface: str -> network interface
    # param count: int -> number of packets (0=infinite)
    # param timeout: int -> seconds to capture
    # param save_file: str -> optional pcap filename to save packets

    print(f"[*] Starting sniffer on interface: {interface}")

    writer = None
    if save_file:
        writer = PcapWriter(save_file, append=True, sync=True)
        print(f"[*] Saving packets to {save_file}")

    try:
        # the 'prn' arg specifies the callback func for each packet
        # the 'count' arg specifies how many packets to sniff
        sniff(iface=interface,
              prn=lambda packet: packet_callback(packet, writer),
              count=count if count > 0 else 0,
              timeout=timeout if timeout > 0 else None,
              store=False)
    except Exception as e:
        print(f"[!] An error occured: {e}")
    finally:
        if writer:
            writer.close()
            print(f"[*] Capture finished, saved to {save_file}")
