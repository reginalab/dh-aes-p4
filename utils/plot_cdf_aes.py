#!/usr/bin/env python


import sys
import csv
import scipy.stats
import numpy as np
from const import logs
from const import colors
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import matplotlib.lines as mlines



NUM_TICKS = 12
NUM_SUBTICKS = NUM_TICKS * 5
MAJ_ALPHA = 1.0
MIN_ALPHA = 0.2

LW = 1.5

X_LABEL = 'Secret-key renewal RTT (ms)'
Y_LABEL = 'Probability [%]'

DATA_TYPE = 'rtt'
GRAPH_TYPE = 'cdf'
FILE_EXTENSION = '.pdf'


def format_axis(axis):
    '''Uses axis to configure the graph.'''
    locator = ticker.MaxNLocator
    axis.xaxis.set_ticks_position('both')
    axis.xaxis.set_major_locator(locator(NUM_TICKS))
    axis.xaxis.set_minor_locator(locator(NUM_SUBTICKS))
    axis.xaxis.grid(which='major', linestyle='-', alpha=MAJ_ALPHA)
    axis.xaxis.grid(which='minor', linestyle='-', alpha=MIN_ALPHA)
    axis.yaxis.grid(which='major', linestyle='-', alpha=MAJ_ALPHA)
    axis.yaxis.grid(which='minor', linestyle='-', alpha=MIN_ALPHA)
    axis.set_axisbelow(True)
    for iter_axis in (axis, axis.twinx()):
        iter_axis.yaxis.set_major_locator(locator(NUM_TICKS))
        iter_axis.yaxis.set_minor_locator(locator(NUM_SUBTICKS))
        iter_axis.set_ylim(axis.get_ylim())


def format_plot(graph, ylabel, xlabel):
    '''Uses pyplot to configure the graph.'''
    plt.xlabel(xlabel, fontweight='bold')
    plt.ylabel(ylabel, fontweight='bold')

    # Legend configuration
    dot1 = mlines.Line2D([], [], color=colors['log_dh_128'], marker='o',
                              label='AES-128', linestyle='')

    dot2 = mlines.Line2D([], [], color=colors['log_dh_192'], marker='o',
                            label='AES-192', linestyle='')

    dot3 = mlines.Line2D([], [], color=colors['log_dh_256'], marker='o',
                            label='AES-256', linestyle='')

    leg = plt.legend(handles=[dot1, dot2, dot3],
                     loc='lower right', fancybox=False,
                     framealpha=1, shadow=False, borderpad=1)

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
    log_name = logs[logexp]['name']

    data = []
    _, axis = plt.subplots()
    
  
    enc_data = []
    dec_data = []
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

        enc_data.append(tmp)
        dec_data.append(tmp_dec)
        print(f"{log}: tempo médio encrypt time: {np.mean(tmp)} ({np.std(tmp)})")
        print(f"{log}: tempo médio decrypt time: {np.mean(tmp_dec)} ({np.std(tmp_dec)}")
        norm = scipy.stats.norm(np.mean(tmp), np.std(tmp))
        norm_dec = scipy.stats.norm(np.mean(tmp_dec), np.std(tmp_dec))    
        cdf = [norm.cdf(i) for i in tmp]
        cdf_dec = [norm.cdf(i) for i in tmp_dec]
        c = ''
        axis.scatter(tmp, cdf, color=colors[log])
        axis.scatter(tmp_dec, cdf_dec, color=colors[log])
    
    enc_xlabel = "AES encryption time (ms)"
    enc_ylabel = "Probability (%)"
    format_plot(colors, enc_ylabel, enc_xlabel)
    format_axis(axis)
    data_type = "enctime"
    plt.savefig(f"{log_dir}figs/{get_filename(logexp, data_type)}", dpi=600)
    _, axis = plt.subplots()
    
    #format_plot(colors)
    #format_axis(axis)
    #plt.savefig(f"{log_dir}figs/{get_filename(logexp)}", dpi=600)
    #_, axis = plt.subplots()
    


if __name__ == '__main__':
    plot_graphs(sys.argv[1])
