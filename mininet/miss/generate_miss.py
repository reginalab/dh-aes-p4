from scapy.all import *

pcaps = ["s2-eth2.cap"]


def rawdump():
    for pcap in pcaps:
        missed_packets = 0
        packets_per_second = 0
        lastsave = 0
        control = False
        started = False
        parsed = rdpcap("../pcaps/" + pcap)
        for pkt in parsed:
            if pkt.type == 0x9999 or pkt.type == 0x812:
                if str(pkt)[-3:-1] == "01":
                    control = True
                if str(pkt)[-3:-1] == "02":
                    print("Packets missed: {}".format(missed_packets))
                    missed_packets = 0
                    control = False

                if control:
                    missed_packets += 1

            if pkt.type == 0x9999:
                if not started:
                    lastsave = int(pkt.time)
                    started = True
                packets_per_second += 1

            if int(pkt.time) - lastsave > 1:
                lastsave = int(pkt.time)
                print("Packets/sec: {}".format(packets_per_second))
                packets_per_second = 0


rawdump()