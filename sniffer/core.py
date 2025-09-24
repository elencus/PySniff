from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from .protocols import *
from .utils import *
from colorama import init, Fore, Style

init(autoreset=True)


def packet_callback(packet, writer=None, proto_filter=None, ip_filter=None, port_filter=None):
    # the main func called for each captured packet
    # it orchestrates the parsing of different layers
    # optionally writes to a pcap file, filters protocols, IPs, ports

    if proto_filter:
        proto_map = {"tcp": TCP, "udp": UDP, "icmp": ICMP}
        if proto_filter.lower() in proto_map and not packet.haslayer(proto_map[proto_filter.lower()]):
            return  # skip

    if ip_filter:
        if IP in packet:
            if packet[IP].src != ip_filter and packet[IP].dst != ip_filter:
                return  # skip
        else:
            return

    if port_filter:
        if TCP in packet or UDP in packet:
            if not (packet[TCP].sport == port_filter and packet[TCP].dport == port_filter or
                    packet[UDP].sport == port_filter and packet[UDP].dport == port_filter):
                return  # skip
        else:
            return

    if writer:
        writer.write(packet)
    print("\n" + "=" * 60)

    eth_info = parse_ethernet_frame(packet)
    print(Fore.CYAN + eth_info)

    # check if the packet has an IP layer
    if IP in packet:
        ip_info, proto = parse_ip_packet(packet[IP])
        print(Fore.MAGENTA + ip_info)

        if proto == "TCP" and TCP in packet:
            tcp_info, payload = parse_tcp_segment(packet[TCP])
            print(Fore.YELLOW + tcp_info)

            # HTTP parsing only works for unencrypted traffic
            if packet.haslayer(HTTPRequest):
                print(Fore.GREEN + parse_http_request(packet[HTTPRequest]))
            elif packet.haslayer(HTTPResponse):
                print(Fore.GREEN + parse_http_response(packet[HTTPResponse]))

            elif packet.haslayer(TLS):
                print(Fore.RED + parse_tls_handshake(packet[TLS]))

            elif payload:
                print(Style.DIM + format_payload_data(payload))



        elif proto == "UDP" and UDP in packet:
            udp_info, payload = parse_udp_datagram(packet[UDP])
            print(Fore.BLUE + udp_info)
            if payload:
                print(Style.DIM + format_payload_data(payload))


        elif proto == "ICMP" and ICMP in packet:
            print(Fore.LIGHTRED_EX + "\t\t[+] ICMP packet")

    print("=" * 60)


def start_sniffing(interface, count=0, timeout=0, save_file=None, bpf_filter=None):
    # starts the sniffing process on a given interface
    # param interface: str -> network interface
    # param count: int -> number of packets (0=infinite)
    # param timeout: int -> seconds to capture
    # param save_file: str -> optional pcap filename to save packets
    # param bpf_filter: str -> filters


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
              filter=bpf_filter,
              store=False)
    except Exception as e:
        print(f"[!] An error occured: {e}")
    finally:
        if writer:
            writer.close()
            print(f"[*] Capture finished, saved to {save_file}")
