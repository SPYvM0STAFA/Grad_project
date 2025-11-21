#!/usr/bin/env python3
from scapy.all import ARP, sniff
import datetime
import logging
import os

# -----------------------------------------------------------
#  CONFIG: Where Suricata normally writes alerts
# -----------------------------------------------------------
FAST_LOG = "/var/log/suricata/fast.log"

# Ensure log directory exists (if running without suricata)
os.makedirs(os.path.dirname(FAST_LOG), exist_ok=True)

# -----------------------------------------------------------
#  Logging format EXACTLY like Suricata fast.log
#  Example:
#  11/21/2025-13:22:01.123456  [**] [1:1000001:1] ARP Spoofing Detected [**] [Priority: 1] {ARP} 192.168.1.5 -> 192.168.1.1
# -----------------------------------------------------------
logging.basicConfig(
    filename=FAST_LOG,
    filemode="a",
    format="%(message)s",
    level=logging.INFO
)

SID = 1000001  # Suricata-like Signature ID
REV = 1

def log_alert(src_ip, src_mac, target_ip):
    ts = datetime.datetime.now().strftime("%m/%d/%Y-%H:%M:%S")
    alert = (
        f"{ts}  [**] [1:{SID}:{REV}] ARP Spoofing Detected "
        f"[**] [Priority: 1] {{ARP}} {src_ip}({src_mac}) -> {target_ip}"
    )
    logging.info(alert)
    print(alert)  # Also print to console


# -----------------------------------------------------------
#  Main ARP callback
# -----------------------------------------------------------
def detect_arp(pkt):
    if pkt.haslayer(ARP) and pkt.op == 2:
        # ARP reply
        src_ip = pkt.psrc
        src_mac = pkt.hwsrc
        target_ip = pkt.pdst

        log_alert(src_ip, src_mac, target_ip)


# -----------------------------------------------------------
#  Start Sniffing
# -----------------------------------------------------------
def main():
    print("ARP Detector started... monitoring ARP packets.")
    print(f"Logging alerts to {FAST_LOG}")
    sniff(filter="arp", prn=detect_arp, store=0)


if __name__ == "__main__":
    main()

