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

colors = ["#03045e", "#023e8a", "#0077b6", "#0096c7", "#00b4d8", "#48cae4", "#90e0ef"]

# Function to generate the boxplot data
def generate_boxplot_data(row):
    return {
        "label": row['Test_name'],  # Use the test name as the label
        "mean": row['connection_time_avg'],  # Mean of the connection times (you can calculate if needed)
        "med": row['Median (Q2)'],  # Median value
        "q1": row['Q1 Value'],  # First Quartile
        "q3": row['Q3 Value'],  # Third Quartile
        "whislo": row['Min Value'],  # Minimum value
        "whishi": row['Max Value'],  # Maximum value
        "fliers": []  # You can add outliers here if needed (e.g. based on IQR method)
    }


def print_plot(path):
    instrumented_path   = os.path.join(path, "instru-clean.csv")
    notinstru_path      = os.path.join(path, "not-instru-clean.csv")


    instrumented    = pd.read_csv(instrumented_path)
    notinstru       = pd.read_csv(notinstru_path)

    # Combine the two DataFrames into one
    combined_df = pd.concat([instrumented, notinstru], ignore_index=True)
    combined_df = combined_df.sort_values(by='Test_name', ascending=True)
    

    save_name = f"test_execution_time.pdf"
    graph_title = f"Real-world scenario Test Execution Time"

    y_name = "Average Execution Time (s)"
    x_name = "Test Name"
    categories  = ["Large", "Medium","Small","Dynamic"]
    labels = ["Instrumented","Not instrumented"]
    group_number = len(labels)

    # Create a dictionary to store the data for each category
    boxplot_data_by_category = {category: [] for category in categories}

    # Group the data by 'Test_name' category (i.e., Large, Medium, Small, Dynamic)
    for index, row in combined_df.iterrows():
        for category in categories:
            if category in row['Test_name']:
                boxplot_data_by_category[category].append(generate_boxplot_data(row))
    
    

    

    fs = 10  # Font size for the plot
    fig, axes  = plt.subplots(nrows=2, ncols=2,figsize=(16, 9))

    # Flatten axes array for easier iteration
    axes = axes.flatten()
    boxs = [None]*4

    for i, category in enumerate(categories):
        # Boxplot data for the current category
        boxplot_data = boxplot_data_by_category[category]
        
        # Create the boxplot on the respective subplot
        boxs[i] = axes[i].bxp(boxplot_data,patch_artist=True)
        
        # Set title and labels
        axes[i].set_title(f'Boxplot for {category} Tests', fontsize=fs)
        axes[i].set_xlabel('Test Name', fontsize=fs)
        axes[i].set_ylabel('Connection Time', fontsize=fs)

        # Optionally, rotate the x-axis labels for better readability
        axes[i].tick_params(axis='x', rotation=0 ,labelsize=fs)
        axes[i].tick_params(axis='y' ,labelsize=fs)
    
    #Color
    curr_color = 0
    for box in boxs:
        for _, patch in enumerate(box['boxes']):
            patch.set_color(colors[curr_color])

            curr_color += 1
            curr_color %= group_number 

    # Legend
    patches = []
    for pos in range(len(labels)):
        patches.append(mpatches.Patch(color=colors[pos], label=labels[pos]))

    for i, _ in enumerate(categories):
        axes[i].legend(handles=patches,fontsize=fs)

    #plt.title(graph_title)
    plt.savefig(save_name)
    plt.show()
        

if __name__ == "__main__":

    if not(len(sys.argv) == 2):
        print("Usage: python analysis.py <dir_path>")
        sys.exit(1)
    path = sys.argv[1]
    print_plot(path)
