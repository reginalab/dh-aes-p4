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
    file_ = '../logs/controller/log_dh_{}.csv'.format(arg[1])
    if glob.glob(file_):
        os.system('rm {}'.format(file_))

    for pcap in pcaps:
        parsed = rdpcap("pcaps/" + pcap)
        for pkt in parsed:
            if pkt.type == 0x812 or pkt.type == 0x9999:
                if pkt.type == 0x812 and pcap == 's1-eth3.cap':
                    s1.append(pkt.time)
                if pkt.type == 0x9999 and pcap == 's2-eth2.cap':
                    s2.append(pkt.time)

    for id, data in enumerate(s1):
        os.system('echo \"%s,%s,%s\" >> %s' % (id, s1[id], s2[id], file_))


rawdump()