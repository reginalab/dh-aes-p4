#!/usr/bin/python

import os

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
    c1 = net.addHost('c1', ip='10.0.0.3/8', mac="00:00:00:00:00:03", inNamespace=False)
    c2 = net.addHost('c2', ip='10.0.0.4/8', mac="00:00:00:00:00:04", inNamespace=False)

    json_file = '../p4src/build/dh_aes.json'

    info('*** Adding P4 Switch\n')
    s1 = net.addSwitch('s1', cls=P4Switch, netcfg=True, loglevel='info',
                       json=json_file, thriftport=50001)
    s2 = net.addSwitch('s2', cls=P4Switch, netcfg=True, loglevel='info',
                       json=json_file, thriftport=50002)

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(s1, s2)

    net.addLink(c1, s1)
    net.addLink(c2, s2)
    net.addLink(c1, c2)

    info('*** Starting network\n')
    net.start()
    net.staticArp()

    bits = '0x2'
    '''if arg[2] == '128':
        bits = '0x0'
    elif arg[2] == '192':
        bits = '0x1'
    elif arg[2] == '256':
        bits = '0x2'''

    cmd1 = 'simple_switch_CLI --thrift-port'
    cmd2 = 'table_add MyIngress.forward'

    c1.cmd('ifconfig c1-eth1 192.168.0.1')
    c2.cmd('ifconfig c2-eth1 192.168.0.2')

    sleep(4)
    # We need these two rules for key negotiation
    #s1.cmd('{} 50001 <<<\"{} set_encrypt 3 0x812 => 2 {}\"'.format(cmd1, cmd2, key0))
    #sleep(1)
    #s2.cmd('{} 50002 <<<\"{} set_decrypt 2 0x812 => 1 {}\"'.format(cmd1, cmd2, key1))
    #sleep(1)
    s1.cmd('{} 50001 <<<\"{} set_egress_spec 2 0x812 => 3\"'.format(cmd1, cmd2))
    sleep(1)
    s2.cmd('{} 50002 <<<\"{} set_egress_spec 2 0x812 => 3\"'.format(cmd1, cmd2))

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

    makeTerm(c1, title='c1', cmd="bash -c 'python test/controller.py 1;'")
    makeTerm(c2, title='c2', cmd="bash -c 'python test/controller.py 2;'")
    makeTerm(h1, title='data', cmd="bash -c 'python test/send_data.py;'")

    info('*** Running CLI\n')
    CLI(net)

    info('*** Kill xterm terminals\n')
    os.system('pkill -9 -f \"xterm\"')

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
