from scapy.all import *
import json, requests, time

VT_API_KEY = "PUT_VT_API_KEY_HERE"
ABUSE_API_KEY = "PUT_ABUSE_KEY_HERE"

LOG_FILE = "/var/log/dns_monitor.json"

def vt_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    return r.json()

def abuse_lookup(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    r = requests.get(url, params=params, headers=headers)
    if r.status_code != 200:
        return None
    return r.json()

def log_eve(entry):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

def process_packet(pkt):
    if pkt.haslayer(DNS) and pkt.haslayer(UDP):

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")

        if pkt[DNS].qr == 0:
            # Query
            domain = pkt[DNSQR].qname.decode()
            entry = {
                "timestamp": timestamp,
                "event_type": "dns_query",
                "src_ip": pkt[IP].src,
                "query": domain
            }
            log_eve(entry)

        if pkt[DNS].qr == 1:
            # Response
            answers = []
            for i in range(pkt[DNS].ancount):
                rr = pkt[DNS].an[i]
                if rr.type == 1: # A Record
                    answers.append(rr.rdata)

            for ip in answers:
                vt = vt_lookup(ip)
                abuse = abuse_lookup(ip)

                entry = {
                    "timestamp": timestamp,
                    "event_type": "dns_response",
                    "src_ip": pkt[IP].src,
                    "resolved_ip": ip,
                    "vt": vt,
                    "abuse": abuse
                }
                log_eve(entry)

def start_sniffing(interface):
    sniff(filter="udp port 53", iface=interface, store=False, prn=process_packet)

