import sys
import scapy.all as scapy

if sys.version_info.major == 3:
    input("Press Enter to continue...")
else:
    raw_input("Press Enter to continue...")

scapy.srp1(scapy.Ether(type=0x812)/("\x00"*33), timeout=0)
