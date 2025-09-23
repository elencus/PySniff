from scapy.all import get_if_list
from sniffer.core import start_sniffing
import argparse


def select_interface():
    interfaces = get_if_list()
    if not interfaces:
        print("[!] No interfaces found.")
        return None

    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f" {i}: {iface}")

    while True:
        try:
            choice = int(input("Select an interface (number): "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print("[!] Invalid choice. Please try again.")
        except ValueError:
            print("[!] Invalid input. Please enter a number.")


def start_cli():
    print(" --- Python Packet Sniffer ---")

    # cli arguments
    parser = argparse.ArgumentParser(description="Python Packet Sniffer")
    parser.add_argument("--count", type=int, default=0,
                        help="Number of packets to capture (0=infinite)")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Time (in seconds) to capture packets (0=infinite)")
    parser.add_argument("--save", type=str, default=None,
                        help="Optional pcap file to save captured files")
    args = parser.parse_args()

    interface = select_interface()
    if not interface:
        return
    try:
        start_sniffing(interface, count=args.count, timeout=args.timeout, save_file=args.save)
    except PermissionError:
        print("\n[!] Permission Error: Please run the script with administrator/root privileges.")
        print("    On Linux/macOS: sudo python3 main.py")
        print("    On Windows: Run PowerShell/CDM as Administrator.")
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user. Goodbye!")
    except Exception as e:
        print(f"\n[!] An unexpected error occured: {e}")
