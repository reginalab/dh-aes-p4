import scapy.all as scapy

for n in range(0, 1):
    scapy.sendp(scapy.Ether(type=0x9999)/("\x70\x6c\x61\x69\x6e\x20\x74\x65\x78\x74\x20\x20\x20\x20\x20\x20"), count=100000)