import argparse
from shadownet.utils.sniffer import start_sniffing

def main():
    parser = argparse.ArgumentParser(description="Shadownet: LAN Anomaly Detection Tool")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", required=True)
    args = parser.parse_args()

    start_sniffing(args.interface)

if __name__ == "__main__":
    main()
