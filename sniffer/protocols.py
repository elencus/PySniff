from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS, TLSServerHello, TLSClientHello


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


def parse_http_request(http_request):
    # parses basic http request headers
    try:
        method = http_request.Method.decode()
        host = http_request.Host.decode()
        path = http_request.Path.decode()
        return f"\t\t[+] HTTP Request: {method} http://{host}{path}"
    except Exception as e:
        print(f"[!] An error occured: {e}")


def parse_http_response(http_response):
    # parses http response
    try:
        status = http_response.Status_Code.decode()
        reason = http_response.Reason_Phrase.decode()
        return f"\t\t[+] HTTP Response: {status} {reason}"
    except Exception as e:
        return f"[!] An error occured: {e}"


def parse_tls_handshake(tls_layer):
    if tls_layer.haslayer(TLSClientHello):
        client_hello = tls_layer[TLSClientHello]
        try:
            sni = client_hello.ext_servername.decode()
        except Exception:
            sni = "N/A"
        return (
            f"\t\t[+] TLS Client Hello\n"
            f"\t\t\t- Version: {client_hello.version}\n"
            f"\t\t\t- Ciphers: {len(client_hello.ciphers)} offered\n"
            f"\t\t\t- SNI: {sni}"
        )
    elif tls_layer.haslayer(TLSServerHello):
        server_hello = tls_layer[TLSServerHello]
        return (
            f"\t\t[+] TLS Server Hello\n"
            f"\t\t\t- Version: {server_hello.version}\n"
            f"\t\t\t- Cipher: {server_hello.cipher}"
        )
    else:
        return "\t\t[+] TLS Record (Encrypted data)"
