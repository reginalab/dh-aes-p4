from scapy.all import *
import os
import glob

pcaps = ["s1-eth1.cap", "s1-eth2.cap", "s2-eth2.cap", "s2-eth1.cap"]


def rawdump():
    s1 = []
    s2 = []

    # generate the df log
    file_ = 'log_noaes_time.csv'
    if glob.glob(file_):
        os.system('rm {}'.format(file_))

    for pcap in pcaps:
        parsed = rdpcap("pcaps/" + pcap)
        for pkt in parsed:
            if pkt.type == 0x9999:
                if pcap == 's1-eth1.cap':
                    s1.append(pkt.time)
                if pcap == 's2-eth1.cap':
                    s2.append(pkt.time)

    for id, data in enumerate(s1):
        os.system('echo \"%s,%s,%s\" >> ../logs/no_crypto/%s' % (id, s1[id], s2[id], file_))


rawdump()