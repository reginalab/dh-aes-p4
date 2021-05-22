import sys

import scapy.all as scapy
from time import sleep

if sys.version_info.major == 3:
    input("Press Enter to continue...")
else:
    raw_input("Press Enter to continue...")

for n in range(0, 11):
    print("\nTriggering Key {}".format(n))
    scapy.srp1(scapy.Ether(type=0x812)/("\x00"*33), timeout=0)
    sleep(10)