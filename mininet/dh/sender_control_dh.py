import sys

import scapy.all as scapy
from time import sleep

if sys.version_info.major == 3:
    input("Press Enter to continue...")
else:
    raw_input("Press Enter to continue...")

for n in range(0, 1000):
    #print("\nTriggering Key {}".format(n))
    sleep(0.100)
    scapy.srp1(scapy.Ether(type=0x812)/("\x00"*33), timeout=0)
