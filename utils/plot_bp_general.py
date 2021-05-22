#!/usr/bin/env python

import sys
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from const import logs
import numpy as np
import csv

NUM_TICKS = 12
NUM_SUBTICKS = 25
MAJ_ALPHA = 1
MIN_ALPHA = 0.1

LW = 1.5

X_LABEL = 'AES key size'
Y_LABEL = 'Secret-key renewal RTT (ms)'

DATA_TYPE = 'rtt'
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
    axis.set_xticklabels(['','DH-128', 'DH-192', 'DH-256', ''])
    axis.xaxis.grid(which='major', linestyle='')
    axis.yaxis.grid(which='major', linestyle='-')
    axis.yaxis.grid(which='minor', linestyle='-')
    axis.set_axisbelow(True)


def format_plot(graph):
    '''Uses pyplot to configure the graph.'''
    plt.xlabel(X_LABEL, fontweight='bold')
    plt.ylabel(Y_LABEL, fontweight='bold')

    # Legend configuration
    leg = plt.legend([graph["boxes"][0], graph["boxes"][1], graph["boxes"][2]],
                     ['DH-128', 'DH-192', 'DH-256'], loc='upper right',
                     fancybox=False, framealpha=1,
                     shadow=False, borderpad=1, fontsize="x-small")

    leg.get_frame().set_edgecolor('black')


def get_filename(conn):
    '''Return filename of the figure.'''
    filename = DATA_TYPE + '-'
    filename += GRAPH_TYPE + '-'
    filename += str(conn) + FILE_EXTENSION
    return filename


def open_file(filename):
    '''Return file content given filename.'''
    with open(filename) as file_:
        return file_.read()

def set_box_color(bp, color):
    plt.setp(bp['boxes'], color=color)
    plt.setp(bp['whiskers'], color=color)
    plt.setp(bp['caps'], color=color)
    plt.setp(bp['medians'], color=color)


def plot_graphs(logexp):
    '''Plot the graphs and save the figures in log_dir.'''
    log_dir = logs[logexp]['dir']
    log_data = logs[logexp]['data']
    log_dh = logs["dh"]["dir"]
    ticks = ['DH-128', 'DH-192', 'DH-256']
    

    data = []
    data2 = []
    _, axis = plt.subplots()

    for log in log_data:
        with open(f'{log_dh}/{log}.csv') as csv_file:
            tmp = []
            for row in csv.reader(csv_file):
                m = float(row[2])
                n = float(row[1])
                tmp.append((m-n)*1000)
            #print(f"{log}: tempo médio - dh time: {np.mean(tmp)} ({np.std(tmp)})")
            data.append(tmp)
        
        with open(f'{log_dir}/{log}.csv') as csv_file:
            tmp = []
            for row in csv.reader(csv_file):
                m = float(row[2])
                n = float(row[1])
                tmp.append((m-n)*1000)
            #print(f"{log}: tempo médio - dh time: {np.mean(tmp)} ({np.std(tmp)})")
            data2.append(tmp)
        
    
    meanpointprops = dict(
        marker='s',
        markerfacecolor='None',
        markeredgewidth=LW)

    boxplot = axis.boxplot(
                data,
                showfliers=False,
                meanprops=meanpointprops,
                meanline=False,
                showmeans=True,
                patch_artist=True,
                notch=False,
                positions=[-0.4, 1.6, 3.6])
    format_graph(boxplot)
    format_plot(boxplot)
    #format_axis(axis)
    ax2 = axis.twinx()

    boxplot2 = ax2.boxplot(
                data2,
                showfliers=False,
                meanprops=meanpointprops,
                meanline=False,
                showmeans=True,
                patch_artist=True,
                notch=False,
                positions=[0.4,2.4,4.4])

    format_graph(boxplot2)
    format_plot(boxplot2)
    format_axis(axis)
    formatter = ticker.ScalarFormatter(useMathText=True)
    formatter.set_scientific(True) 
    formatter.set_powerlimits((-3,1)) 
    axis.yaxis.set_major_formatter(formatter) 
    #plt.show()
    plt.xticks(range(0, len(ticks) * 2, 2), ticks)
    #plt.xlim(-2, len(ticks)*2)
    #plt.ylim(0, 8)
    plt.tight_layout()
    plt.savefig(f"{log_dir}figs/{get_filename(logexp)}", dpi=600)
    _, axis = plt.subplots()
    data.clear()



if __name__ == '__main__':
    plot_graphs('controller_dh')
