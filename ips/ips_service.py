import signal
import sys
from main import start_ips, stop_ips

def handle_shutdown(signum, frame):
    print("[!] Received shutdown signal. Cleaning up...")
    stop_ips()
    sys.exit(0)

def main():
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    print("[+] Starting IPS Service...")
    start_ips()

if __name__ == "__main__":
    main()
