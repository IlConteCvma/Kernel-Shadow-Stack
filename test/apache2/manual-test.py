import subprocess
import sys
import numpy as np
import os, shutil
import locale
import pandas as pd
import re
import csv
import time

TEST_NUMBER = 500
NUM_CONNECT = 1000

# Configuration for the httperf tests
TESTS = [
    #{'server': 'test-static.com', ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    #Page HTML HUGE
    #{'server': 'test-static.com','uri': 'index.html' ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'name':'Large','server': 'test-static.com','uri': 'index.html' ,'port': 80, 'num_connections': NUM_CONNECT},
    #{'server': 'test-static.com','uri': 'index.html' ,'port': 80, 'num_connections': 200, 'num_requests': 2000},
    #Page HTML MEDIUM
    #{'server': '127.0.0.1', 'uri':'index.html' ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'name':'Medium','server': '127.0.0.1', 'uri':'index.html' ,'port': 80, 'num_connections': NUM_CONNECT},
    #{'server': '127.0.0.1', 'uri':'index.html' ,'port': 80, 'num_connections': 200, 'num_requests': 2000},
    #Page HTML SMALL
    #{'server': 'test-ssmall.com', 'uri': 'index.html' ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'name':'Small','server': 'test-ssmall.com', 'uri': 'index.html' ,'port': 80, 'num_connections': NUM_CONNECT},
    #{'server': 'test-ssmall.com', 'uri': 'index.html' ,'port': 80, 'num_connections': 200, 'num_requests': 2000},

    #Dynamic site
    #{'server': 'test-dynamic.com' , 'uri': '/login_user.php?user_email=anindodas@yahoo.in&user_password=anindo', 'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'name':'Dynamic','server': 'test-dynamic.com' , 'uri': '/login_user.php?user_email=anindodas@yahoo.in&user_password=anindo', 'port': 80, 'num_connections': NUM_CONNECT},
    #{'server': 'test-dynamic.com' , 'uri': '/login_user.php?user_email=anindodas@yahoo.in&user_password=anindo', 'port': 80, 'num_connections': 200, 'num_requests': 2000},

    # Add more test configurations as needed
]

request_info = {
    "Test name" : [],
    "Total connections" : [],
    "Duration" : [],
    "Conn Rate" : [],
    "Reply Size" : [],
}


def run_httperf(test):
    
    #cmd = [
    #    'httperf',
    #    '--server', test['server'],
    #    '--uri', test['uri'],
    #    '--port', str(test['port']),
    #    '--num-conns',str(test['num_connections']),
    #    #'--num-calls', str(test['num_requests']),
    #    '--rate', '0' ,
    #    '-timeout', '1'
    #]

    cmd = f"httperf --server {test['server']} --port {str(test['port'])} --uri {test['uri']} --num-conns {str(test['num_connections'])} --rate 0 --timeout 1"
    
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, executable="/bin/bash")
    return result




# Function to parse the httperf output and extract relevant metrics
def parse_output(test_name,output):
    request_info["Test name"].append(test_name)
    res = re.search("Total: connections \d+ requests (\d+) ", output)
    request_info["Total connections"].append(res.group(1))
    res = re.search(" test-duration (\d+\.\d+) s", output)
    request_info["Duration"].append(res.group(1))
    res = re.search("Connection rate: (\d+\.\d+) conn/s", output)
    request_info["Conn Rate"].append(res.group(1))
    res = re.search("oter \d+\.\d+ \(total (\d+\.\d+)\)", output)
    request_info["Reply Size"].append(res.group(1))



def run_tests_and_save_to_csv(filename):
    
    for test in TESTS:
        # command
        print(f"Running httperf test on {test['server']}:{test['port']}...")
        
        print(f"Running command {test['server']}\tTest size: {TEST_NUMBER}")

        for i in range(0, TEST_NUMBER):
            print(f"Run number{i}")

            output = run_httperf(test)
            #print(output.stdout)
            parse_output(test['name'],output.stdout)
    
        results = pd.DataFrame(request_info)
        #print(results)

        results.to_csv(filename, index=False)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <file_name>")
        sys.exit(1)

    file_name = sys.argv[1]
    print(f"File name received: {file_name}")

    run_tests_and_save_to_csv(str(file_name))
    print(f"Tests completed. Results saved to {file_name}.")
