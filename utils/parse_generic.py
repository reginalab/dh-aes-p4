#!/usr/bin/env python


import csv
import numpy as np
from const import logs


def parse_noaes():
    log_dir = logs['no-aes']['dir']
    tmp = []
    with open(f'{log_dir}log_noaes_time.csv') as csv_file:
        
        for row in csv.reader(csv_file):
            m = float(row[2])
            n = float(row[1])
            tmp.append((m-n)*1000)
    
    mean = np.mean(tmp)/1000
    print(f"Tempo médio no-aes: {np.mean(tmp)}ms ({np.std(tmp)})")
    #mean_encdec = (np.mean(tmp) + np.mean(tmp_dec))/1000
    tr = "%.012f" % (0.0000286102/mean)
    print(f"Throughput no-aes: {tr}")


def parse_statickey():
    log_dir = logs['dh']['dir']
    tmp = []
    with open(f'{log_dir}log_dh_statickey.csv') as csv_file:
        
        for row in csv.reader(csv_file):
            m = float(row[2])
            n = float(row[1])
            tmp.append((m-n)*1000)
    
    mean = np.mean(tmp)
    print(f"Tempo médio DH Static key {mean}")


if __name__ == '__main__':
    parse_noaes()
    parse_statickey()
