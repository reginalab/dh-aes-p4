#!/usr/bin/python

import os
import sys

from time import sleep

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.bmv2 import P4Switch
from mininet.term import makeTerm


def add_table_entries(s1, s2, cmd1):
    table = '../utils/table.txt'
    info('*** Adding data to tables, please wait until s1 and s2 xterms get closed.\n')
    makeTerm(s1, title='s1', cmd="bash -c 'echo \"adding table entries...\n"
                                 "please wait for this terminal to close. \" &&"
                                 " {} 50001 < {} >/dev/null 2>&1;'".format(cmd1, table))
    makeTerm(s2, title='s2', cmd="bash -c 'echo \"adding table entries...\n"
                                 "please wait for this terminal to close. \" &&"
                                 " {} 50002 < {} >/dev/null 2>&1;'".format(cmd1, table))


def topology():
    'Create a network.'
    net = Mininet_wifi()

    for fname in os.listdir('pcaps'):
        if fname.endswith('.cap'):
            os.system('cd pcaps && rm -r {}'.format(fname))

    os.system("sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    os.system("sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    os.system("sudo sysctl -w net.ipv6.conf.default.autoconf=0")
    os.system("sudo sysctl -w net.ipv6.conf.lo.autoconf=0")

    info('*** Adding stations/hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/8', mac="00:00:00:00:00:01")
    h2 = net.addHost('h2', ip='10.0.0.2/8', mac="00:00:00:00:00:02")
    c1 = net.addHost('c1', ip='10.0.0.3/8', mac="00:00:00:00:00:03")

    arg = sys.argv
    file = arg[1]
    if arg[1] == 'miss' or arg[1] == 'dh' or arg[1] == 'aes' or arg[1] == 'test':
        file = 'dh-aes'
    elif arg[1] == 'controller':
        file = 'controller_' + arg[2]
    json_file = '../p4src/build/{}.json'.format(file)

    info('*** Adding P4 Switch\n')
    s1 = net.addSwitch('s1', cls=P4Switch, netcfg=True, loglevel='info',
                       json=json_file, thriftport=50001)
    s2 = net.addSwitch('s2', cls=P4Switch, netcfg=True, loglevel='info',
                       json=json_file, thriftport=50002)
    if arg[1] == 'controller':
        b1 = net.addSwitch('b1')

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(s1, s2)
    if arg[1] == 'controller':
        net.addLink(b1, s1)
        net.addLink(b1, s2)
        net.addLink(b1, c1)
    else:
        net.addLink(c1, s1)

    info('*** Starting network\n')
    net.start()
    net.staticArp()

    if arg[1] == 'test':
        key0 = '0x4df2971c482e031fb3bd72fef68ff4905eb26bcd6f3eee3dca6d12131b251976'
        key1 = '0x80b9058aa1c3297837416c43409340e61e16dbc7799c5e2ed35ed55b92da4692'
    else:
        key0 = '0x0000000000000000000000000000000000000000000000000000000000000000'
        key1 = '0x0000000000000000000000000000000000000000000000000000000000000000'

    bits = '0x0'
    if arg[1] != 'no_crypto' and arg[1] != 'embedded' and arg[1] != 'controller':
        if arg[2] == '128':
            bits = '0x0'
        elif arg[2] == '192':
            bits = '0x1'
        elif arg[2] == '256':
            bits = '0x2'

    cmd1 = 'simple_switch_CLI --thrift-port'
    cmd2 = 'table_add MyIngress.forward'


    sleep(4)
    if arg[1] == 'no_crypto' or arg[1] == 'embedded':
        s1.cmd('{} 50001 <<<\"{} set_egress_spec 1 => 2\"'.format(cmd1, cmd2))
        sleep(1)
        s1.cmd('{} 50001 <<<\"{} set_egress_spec 2 => 1\"'.format(cmd1, cmd2))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_egress_spec 2 => 1\"'.format(cmd1, cmd2))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_egress_spec 1 => 2\"'.format(cmd1, cmd2))
        if arg[1] == 'embedded':
            # Adding table entries
            add_table_entries(s1, s2, cmd1)
    elif arg[1] == 'controller':
        s1.cmd('{} 50001 <<<\"{} set_egress_spec 1 => 2\"'.format(cmd1, cmd2))
        sleep(1)
        s1.cmd('{} 50001 <<<\"{} set_egress_spec 2 => 1\"'.format(cmd1, cmd2))
        sleep(1)
        s1.cmd('{} 50001 <<<\"{} set_egress_spec 3 => 2\"'.format(cmd1, cmd2))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_egress_spec 1 => 2\"'.format(cmd1, cmd2))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_egress_spec 2 => 1\"'.format(cmd1, cmd2))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_egress_spec 3 => 2\"'.format(cmd1, cmd2))
        # Adding table entries
        add_table_entries(s1, s2, cmd1)
    else:
        # We need these two rules for key negotiation
        s1.cmd('{} 50001 <<<\"{} set_encrypt 3 0x812 => 2 {}\"'.format(cmd1, cmd2, key0))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_decrypt 2 0x812 => 1 {}\"'.format(cmd1, cmd2, key1))
        sleep(1)
        s1.cmd('{} 50001 <<<\"{} set_egress_spec 2 0x812 => 3\"'.format(cmd1, cmd2))

        sleep(1)
        s1.cmd('{} 50001 <<<\"{} set_flag 1 0x9999 => 2 0x3 {}\"'.format(cmd1, cmd2, bits))
        sleep(1)
        s2.cmd('{} 50002 <<<\"{} set_flag 2 0x9999 => 1 0x0 {}\"'.format(cmd1, cmd2, bits))
        # Adding table entries
        add_table_entries(s1, s2, cmd1)

    makeTerm(s1, title='eth1', cmd="bash -c 'tcpdump -i s1-eth1 -w pcaps/s1-eth1.cap;'")
    makeTerm(s1, title='eth2', cmd="bash -c 'tcpdump -i s1-eth2 -w pcaps/s1-eth2.cap;'")
    makeTerm(s1, title='eth3', cmd="bash -c 'tcpdump -i s1-eth3 -w pcaps/s1-eth3.cap;'")
    makeTerm(s2, title='eth1', cmd="bash -c 'tcpdump -i s2-eth1 -w pcaps/s2-eth1.cap;'")
    makeTerm(s2, title='eth2', cmd="bash -c 'tcpdump -i s2-eth2 -w pcaps/s2-eth2.cap;'")
    if arg[1] == 'controller':
        makeTerm(s2, title='eth3', cmd="bash -c 'tcpdump -i s2-eth3 -w pcaps/s2-eth3.cap;'")

    if arg[1] == 'no_crypto':
        makeTerm(h1, title='sender', cmd="bash -c 'python no_crypto/sender_data_miss.py;'")
    elif arg[1] == 'embedded':
        makeTerm(h1, title='sender', cmd="bash -c 'python embedded/sender.py;'")
    elif arg[1] == 'controller':
        makeTerm(h1, title='sender', cmd="bash -c 'python controller/sender.py;'")
        makeTerm(c1, title='sniffer', cmd="bash -c 'python controller/sniffer.py;'")
    elif arg[1] == 'miss':
        makeTerm(h1, title='sender', cmd="bash -c 'python miss/sender_data_miss.py;'")
        makeTerm(c1, title='sender', cmd="bash -c 'python miss/sender_control_miss.py;'")
    elif arg[1] == 'dh':
        makeTerm(c1, title='sender', cmd="bash -c 'python dh/sender_control_dh.py;'")
    elif arg[1] == 'aes':
        makeTerm(c1, title='sender', cmd="bash -c 'python aes/sender_control_aes.py;'")
        makeTerm(h1, title='sender', cmd="bash -c 'python aes/sender_data_aes.py;'")
    elif arg[1] == 'test':
        makeTerm(c1, title='sender', cmd="bash -c 'python test/sender_control_aes.py;'")
        makeTerm(h1, title='sender', cmd="bash -c 'python test/sender_data_aes.py;'")

    if arg[1] == 'controller':
        b1.cmd('ovs-ofctl add-flow b1 in_port=1,actions=3')
        b1.cmd('ovs-ofctl add-flow b1 in_port=2,actions=3')
        b1.cmd('ovs-ofctl add-flow b1 in_port=3,dl_type=0x813,actions=1')
        b1.cmd('ovs-ofctl add-flow b1 in_port=3,dl_type=0x814,actions=2')

    info('*** Running CLI\n')
    CLI(net)

    info('*** Kill xterm terminals\n')
    os.system('pkill -9 -f \"xterm\"')

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
