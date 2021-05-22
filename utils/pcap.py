from scapy.all import *

pcaps = ["s1-eth3.cap", "s1-eth2.cap", "s2-eth2.cap", "s1-eth1.cap", "s2-eth1.cap"]


def rawdump():
    for pcap in pcaps:
        parsed = rdpcap("../mininet/pcaps/" + pcap)
        print("\n============= Ethernet Frame {%s} ===========\n" % pcap)
        for pkt in parsed:
            if pkt.type == 0x9999 or pkt.type == 0x812:
                a = pkt.payload
                hexdump(a)


rawdump()
