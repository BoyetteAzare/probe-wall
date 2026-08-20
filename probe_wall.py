from scapy.all import *
import csv

oui_lookup = {}
with open("oui_lookup.csv", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        prefix = row["oui"].upper()
        vendor = row["manufacturer"]
        oui_lookup[prefix] = vendor

def build_fake_config(ssid, mac_addr, vendor):
    config = f"""interface=wlan1
ssid={ssid}
device_vendor={vendor}
channel=6
hw_mode=g"""
    warning = "This is NOT being run. This is what an attacker could run using the info your phone gave."
    return config, warning


packets = rdpcap("Wireshark_802_11.pcap")
probes = [pkt for pkt in packets if pkt.haslayer(Dot11ProbeReq)]

for p in probes:
    mac = p.addr2
    prefix = mac[:8].upper()
    vendor = oui_lookup.get(prefix, "Unknown")
    raw_ssid = p[Dot11Elt].info
    ssid = raw_ssid.decode(errors="ignore")
    if ssid == "":
        continue
    config, warning = build_fake_config(ssid, mac, vendor)
    print(config)
    print(warning)
    print("---")