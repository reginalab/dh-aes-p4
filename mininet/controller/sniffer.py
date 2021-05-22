from scapy.all import *
import os
import binascii


def pkt_callback(pkt):
    key = get_key() + '\x04'
    if pkt[Ether].src == "00:00:00:00:00:01":
        print("Sending a private key to the switch")
        if pkt.type == 0x812:
            sendp(Ether(type=0x813) / key, count=1)
        elif pkt.type == 0x813:
            sendp(Ether(type=0x814) / key, count=1)

def get_key():
    if sys.version_info.major == 3:
        return binascii.hexlify(os.urandom(16)).decode("utf-8")
    else:
        return binascii.hexlify(os.urandom(16))


sniff(iface="c1-eth0", filter='ether proto 0x812 or ether proto 0x813', prn=pkt_callback, store=0)