from cProfile import label
from hashlib import new
from tokenize import group
from unittest.mock import patch
import pandas as pd
import numpy as np
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon
from itertools import repeat
import matplotlib
import os
import sys


matplotlib.rcParams.update({'font.size': 25})

NUM_CSV = 4

times = [0]*NUM_CSV

def print_plot(path):
    colors = ["#03045e", "#023e8a", "#0077b6", "#0096c7", "#00b4d8", "#48cae4", "#90e0ef"]
    instrumented_path   = os.path.join(path, "100-instru.csv")
    notinstru_path      = os.path.join(path, "not-instru.csv")
    instrumented33_path   = os.path.join(path, "33-instru.csv")
    instrumented66_path   = os.path.join(path, "66-instru.csv")

    times[0] = pd.read_csv(notinstru_path)
    times[1] = pd.read_csv(instrumented33_path)
    times[2] = pd.read_csv(instrumented66_path)
    times[3] = pd.read_csv(instrumented_path)

    test_names = ["4KB","10KB","25KB","2MB","Dynamic"]
    #labels = ["Not instrumented","Instrumented (Full)"]
    labels = ["Not instrumented","Instrumented (33%)","Instrumented (66%)","Instrumented (Full)"]

    save_name = f"test_execution_time.pdf"
    graph_title = f"Real-world scenario"
    y_name = "Response Time (s x 1000 req)"
    x_name = "Configuration"

    ys = []

    for test in test_names:
        for time in times:
            curr_times = time.loc[(time["Test name"] == test)]
            new_arr = np.array(curr_times["Duration"])
            new_arr = new_arr.astype(float)
            ys.append(new_arr)

    xs = test_names

    #color = [colors[0], colors[3]]
    color = [colors[0], colors[3],colors[1],colors[2]]
    group_number = len(labels)

    ###############################################################



    group_number = len(labels)
    # if (len(ys) < 4):
    #     barWidth = 0.25
    # else:
    #     barWidth = 0.12

    barWidth = 0.2
    barSpace = 0.05
    groupSpace = 5*barSpace
    br = [] 
    curr = 0.01
    for i in range(0, len(ys)):
        if i == 0 or (i+1) % (group_number) != 0:    
            br.append(curr)
            curr += barWidth + barSpace
        else:
            br.append(curr)
            curr += barWidth + groupSpace
            
    #br3 = [x + barWidth + barSpace for x in br2]
    #br4 = [x + barWidth + barSpace for x in br3]
    #br5 = [x + barWidth + barSpace for x in br4]

    ticks = []
    for i in xs:
        #ticks.extend([ i, ""]) #BUG
        ticks.extend([ "",i, "",""]) #BUG

    print(len(ticks))
    print(len(ys))
    fig, ax = plt.subplots(figsize=(16, 9))
    bp = ax.boxplot(ys, positions=br, widths=[barWidth for _ in ys], labels=ticks, showfliers=False)


    num_boxes = len(ys)
    medians = np.empty(num_boxes)
    for i in range(num_boxes):
        box = bp['boxes'][i]
        box_x = []
        box_y = []
        for j in range(5):
            box_x.append(box.get_xdata()[j])
            box_y.append(box.get_ydata()[j])
        box_coords = np.column_stack([box_x, box_y])
        ax.add_patch(Polygon(box_coords, facecolor=colors[i % group_number]))
        
        # median
        med = bp['medians'][i]
        median_x = []
        median_y = []
        for j in range(2):
            median_x.append(med.get_xdata()[j])
            median_y.append(med.get_ydata()[j])
            ax.plot(median_x, median_y, 'k')#, label=labels[i])
        medians[i] = median_y[0]
        
        # mean
        # ax.plot(np.average(med.get_xdata()), np.average(ys[i]),
        #          color='w', markeredgecolor='k')
        
    curr_color = 0
    for ind, patch in enumerate(bp['boxes']):
        patch.set_color(colors[curr_color])

        curr_color += 1
        curr_color %= group_number 

    plt.xlabel(x_name)
    plt.ylabel(y_name)
    # plt.xticks([r + barWidth + 20*barSpace for r in range(len(ys))], xs)

    patches = []
    for pos in range(len(labels)):
        patches.append(mpatches.Patch(color=colors[pos], label=labels[pos]))

    ax.legend(handles=patches)

    # ax.legend(labels)
    plt.title(graph_title)

    plt.savefig(save_name)

    plt.show()


if __name__ == "__main__":

    if not(len(sys.argv) == 2):
        print("Usage: python analysis.py <dir_path>")
        sys.exit(1)
    path = sys.argv[1]
    print_plot(path)


