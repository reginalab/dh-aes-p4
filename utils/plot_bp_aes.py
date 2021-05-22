#!/usr/bin/env python

import sys
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from const import logs
import csv

NUM_TICKS = 12
NUM_SUBTICKS = 25
MAJ_ALPHA = 1
MIN_ALPHA = 0.1

LW = 1.5

X_LABEL = ''
Y_LABEL = ''

DATA_TYPE = 'enc'
GRAPH_TYPE = 'boxplot'
FILE_EXTENSION = '.eps'


def format_graph(graph):
    '''Configure graph properties.'''
    colors = ['black', 'black', 'red', 'red', 'purple', 'purple']
    for cap, color in zip(graph['caps'], colors):
        cap.set(color=color, linewidth=LW)

    for whisker, color in zip(graph['whiskers'], colors):
        whisker.set(color=color, linewidth=LW)

    colors = ['black', 'red', 'purple', 'purple']
    for mean, color in zip(graph['means'], colors):
        mean.set(markeredgecolor=color, linewidth=LW)

    for median, color in zip(graph['medians'], colors):
        median.set(color=color, linewidth=LW)

    for patch, color in zip(graph['boxes'], colors):
        patch.set_facecolor("None")
        patch.set_edgecolor(color)
        patch.set_linewidth(LW)

def format_axis(axis):
    '''Uses axis to configure the graph.'''
    locator = ticker.MaxNLocator
    axis.xaxis.set_ticks_position('both')
    axis.xaxis.set_ticks([0, 1, 2 ,3,4])
    axis.set_xticklabels(['','AES-128', 'AES-192', 'AES-256', ''])
    axis.xaxis.grid(which='major', linestyle='')
    axis.yaxis.grid(which='major', linestyle='-')
    axis.yaxis.grid(which='minor', linestyle='-')
    axis.set_axisbelow(True)


def format_plot1(graph, ylabel, xlabel):
    '''Uses pyplot to configure the graph.'''
    plt.xlabel(xlabel, fontweight='bold')
    plt.ylabel(ylabel, fontweight='bold')

    # Legend configuration
    leg = plt.legend([graph["boxes"][0], graph["boxes"][1], graph["boxes"][2]],
                     ['AES-128', 'AES-192', 'AES-256'], loc='upper right',
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
            

    meanpointprops = dict(marker='s', markerfacecolor='None', markeredgewidth=LW)
    boxplot_enc = axis.boxplot(
                enc_data,
                showfliers=False,
                meanprops=meanpointprops,
                meanline=False,
                showmeans=True,
                patch_artist=True,
                notch=False,
                labels=['ENC-128', 'ENC-192', 'ENC-256'])

    format_graph(boxplot_enc)
    enc_xlabel = "AES implementation"
    enc_ylabel = "Encryption time (ms)"
    format_plot1(boxplot_enc, enc_ylabel, enc_xlabel)
    format_axis(axis)
    data_type = "enctime"
    plt.savefig(f"{log_dir}figs/{get_filename(logexp,data_type)}", dpi=600)
    _, axis = plt.subplots()
    boxplot_dec = axis.boxplot(
                dec_data,
                showfliers=False,
                meanprops=meanpointprops,
                meanline=False,
                showmeans=True,
                patch_artist=True,
                notch=False,
                labels=['ENC-128', 'ENC-192', 'ENC-256'])

    format_graph(boxplot_dec)
    enc_xlabel = "AES implementation"
    enc_ylabel = "Decryption time (ms)"
    format_plot1(boxplot_dec, enc_ylabel, enc_xlabel)
    format_axis(axis)
    data_type = "dectime"
    plt.savefig(f"{log_dir}figs/{get_filename(logexp,data_type)}", dpi=600)



                        
                #n = float(row[2])-float(row[1])
                #tmp.append(n*1000)
            #data.append(tmp)
    

  



if __name__ == '__main__':
    plot_graphs(sys.argv[1])
