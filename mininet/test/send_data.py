import sys

import scapy.all as scapy

while True:
    if sys.version_info.major == 3:
        input("Press Enter to continue...")
    else:
        raw_input("Press Enter to continue...")

    scapy.sendp(scapy.Ether(type=0x9999)/"\x70\x6c\x61\x69\x6e\x20\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20", count=1)

