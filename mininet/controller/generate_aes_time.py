from scapy.all import *
import os
import glob
import sys

pcaps = ["s1-eth1.cap", "s1-eth2.cap", "s2-eth2.cap", "s2-eth1.cap"]


def rawdump():
    s11 = []
    s12 = []
    arg = sys.argv

    # generate the df log
    file_ = '../logs/controller/log_encdec_time_{}.csv'.format(arg[1])
    if glob.glob(file_):
        os.system('rm {}'.format(file_))

    for pcap in pcaps:
        parsed = rdpcap("pcaps/" + pcap)
        for pkt in parsed:
            if pkt.type == 0x9999:
                if pcap == 's1-eth1.cap':
                    s11.append(pkt.time)
                if pcap == 's1-eth2.cap':
                    s12.append(pkt.time)

    os.system('echo \"Encrypt,,\" >> %s' % file_)
    for id, data in enumerate(s11):
        os.system('echo \"%s,%s,%s\" >> %s' % (id, s11[id], s12[id], file_))

    s21 = []
    s22 = []
    for pcap in pcaps:
        parsed = rdpcap("pcaps/" + pcap)
        for pkt in parsed:
            if pkt.type == 0x9999:
                if pcap == 's2-eth2.cap':
                    s21.append(pkt.time)
                if pcap == 's2-eth1.cap':
                    s22.append(pkt.time)

    os.system('echo \"\nDecrypt,,\" >> %s' % file_)
    for id, data in enumerate(s21):
        os.system('echo \"%s,%s,%s\" >> %s' % (id, s21[id], s22[id], file_))


rawdump()