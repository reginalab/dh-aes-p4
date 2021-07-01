import sys
import os
import random
import scapy.all as scapy
import subprocess

from time import sleep

cmd1 = 'simple_switch_CLI --thrift-port'
cmd2 = 'table_add MyIngress.forward'
cmd3 = 'table_modify MyIngress.forward'
arg = sys.argv
key_id = 0
key0 = hex(random.getrandbits(256))
cmd = '{} 5000{} <<< \"{} set_encrypt 3 0x812 => 2 {}\"'.format(cmd1, arg[1], cmd2, key0)
subprocess.run(['bash', '-c', cmd])

if sys.version_info.major == 3:
    input("Press Enter to continue...")
else:
    raw_input("Press Enter to continue...")

while True:
    sleep(10)
    print('Pushing Key ID #{}'.format(key_id))
    key0 = hex(random.getrandbits(256))
    cmd = '{} 5000{} <<< \"{} set_encrypt 2 => 2 {}\"'.format(cmd1, arg[1], cmd3, key0)
    subprocess.run(['bash', '-c', cmd])
    scapy.srp1(scapy.Ether(type=0x812)/("\x00"*33), timeout=0, iface='c{}-eth0'.format(arg[1]))
    key_id += 1
