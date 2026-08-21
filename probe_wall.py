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




def handle_packet(p):
    if not p.haslayer(Dot11ProbeReq):
        return
    mac = p.addr2
    try:
        rssi = p[RadioTap].dBm_AntSignal
    except Exception:
        rssi = None
    print("RSSI:", rssi)
    prefix = mac[:8].upper()
    vendor = oui_lookup.get(prefix, "Unknown")
    raw_ssid = p[Dot11Elt].info
    ssid = raw_ssid.decode(errors="ignore")
    if ssid == "":
        return
    config, warning = build_fake_config(ssid, mac, vendor)
    print(config)
    print(warning)
    print("---")

sniff(iface="wlan1mon", prn=handle_packet, store=False)
