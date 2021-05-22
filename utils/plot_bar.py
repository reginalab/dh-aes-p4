#!/usr/bin/env python

import sys
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
from const import logs
import csv

NUM_TICKS = 12
NUM_SUBTICKS = 10
MAJ_ALPHA = 1
MIN_ALPHA = 0.1

LW = 1.5

GRAPH_TYPE = 'bar'
FILE_EXTENSION = '.eps'


def format_axis(axis):
    '''Uses axis to configure the graph.'''
    locator = ticker.MaxNLocator
    axis.xaxis.set_ticks_position('both')
    axis.yaxis.set_major_locator(locator(NUM_SUBTICKS))
    #axis.xaxis.set_minor_locator(locator(NUM_SUBTICKS))
    axis.xaxis.set_ticks([0, 1, 2])
    axis.set_xticklabels(['AES-128', 'AES-192', 'AES-256'])
    axis.xaxis.grid(which='major', linestyle='')
    axis.yaxis.grid(which='major', linestyle='-')
    axis.yaxis.grid(which='minor', linestyle='-')
    axis.set_axisbelow(True)


def format_plot(graph, ylabel, xlabel):
    '''Uses pyplot to configure the graph.'''
    plt.xlabel(xlabel, fontweight='bold')
    plt.ylabel(ylabel, fontweight='bold')

    # Legend configuration
    leg = plt.legend(loc='upper right',
                     fancybox=False, framealpha=1,
                     shadow=False, borderpad=1, fontsize="x-small")

    leg.get_frame().set_edgecolor('black')


def get_filename(conn, data_type):
    '''Return filename of the figure.'''
    filename = data_type + '-'
    filename += GRAPH_TYPE + '-'
    filename += str(conn) + FILE_EXTENSION
    return filename


def open_file(filename):
    '''Return file content given filename.'''
    with open(filename) as file_:
        return file_.read()


def plot_graphs(logexp):
    '''Plot the graphs and save the figures in log_dir.'''
    log_dir = logs[logexp]['dir']
    log_data = logs[logexp]['data']
    log_dir_aes = logs["embedded"]["dir"]
    #log_name = logs[logexp]['name']

    data = []
    #_, axis = plt.subplots()
  
    width = 0.9
    enc_data = []
    dec_data = []
    
    means_enc = []
    means_dec = []

    std_enc = []
    std_dec = []

    for log in log_data:
        csv_enc_data = None
        csv_dec_data = None
        with open(f'{log_dir}/{log}.csv') as csv_file:
            tmp = []
            for row in csv.reader(csv_file):
                if row != []:
                    if row[0] == "Encrypt":
                        my_csv_data = list(csv.reader(csv_file))
                        csv_enc_data = my_csv_data[1:1000]
                        #csv_dec_data = my_csv_data[1003:2003]

        with open(f'{log_dir_aes}/{log}.csv') as csv_file:
            tmp = []
            for row in csv.reader(csv_file):
                if row != []:
                    if row[0] == "Encrypt":
                        my_csv_data = list(csv.reader(csv_file))
                        #csv_enc_data = my_csv_data[1:1000]
                        csv_dec_data = my_csv_data[1003:2003]
        
        tmp = []
        tmp_dec = []
        for x in csv_enc_data:
            m = float(x[2])
            n = float(x[1])
            tmp.append((m-n)*1000)
        for x in csv_dec_data:
            m = float(x[2])
            n = float(x[1])
            tmp_dec.append((m-n)*1000)

        means_enc.append(np.mean(tmp))
        means_dec.append(np.mean(tmp_dec))
        #print(means_enc, means_dec)
        std_enc.append(np.std(tmp))
        std_dec.append(np.std(tmp_dec))

        mean_encdec = (np.mean(tmp) + np.mean(tmp_dec))/1000
        tr = "%.012f" % (0.0000286102/mean_encdec)
        #t = float(tr)*1048576
        #print(t)
        #print(f"Throughput {log[-3:]}: {tr}")
        #print(f"Throughput dec {log[-3:]}: {30/np.mean(tmp_dec)}")

    
    labels = ['AES-128', 'AES-192', 'AES-256']
 

    x = np.arange(len(labels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width/1.9, means_enc, width, label='Controller-based encryption', yerr=std_enc, align='center',ecolor='black', capsize=10, color=['grey'])
    rects2 = ax.bar(x + width/1.9, means_dec, width, label='Embedded encryption', yerr=std_dec, align='center',ecolor='black', capsize=10, color=['silver'])
    ax.set_ylim([0,105])
    format_axis(ax)
    format_plot(ax,"Average time (ms)", "AES key size")
    


    fig.tight_layout()
    data_type = "encdectime"
    plt.savefig(f"{log_dir}figs/{get_filename(logexp, data_type)}", dpi=600)
    _, axis = plt.subplots()
    #plt.show()
   


if __name__ == '__main__':
    plot_graphs('controller_aes')
