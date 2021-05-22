from scapy.all import *
import os
import glob
import sys

pcaps = ["s1-eth3.cap", "s2-eth2.cap"]


def rawdump():
    s1 = []
    s2 = []
    arg = sys.argv

    # generate the df log
    file_ = '../logs/dh/log_dh_{}.csv'.format(arg[1])
    if glob.glob(file_):
        os.system('rm {}'.format(file_))

    for pcap in pcaps:
        parsed = rdpcap("pcaps/" + pcap)
        for pkt in parsed:
            if pkt.type == 0x812:
                if str(pkt)[-3:-1] == "00" and pcap == 's1-eth3.cap':
                    s1.append(pkt.time)
                if str(pkt)[-3:-1] == "02" and pcap == 's2-eth2.cap':
                    s2.append(pkt.time)

    for id, data in enumerate(s1):
        os.system('echo \"%s,%s,%s\" >> %s' % (id, s1[id], s2[id], file_))


rawdump()