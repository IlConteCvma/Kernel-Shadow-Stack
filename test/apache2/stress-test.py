import subprocess
import csv
import time
import sys

# Configuration for the httperf tests
TESTS = [
    #{'server': 'test-static.com', ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    #Page HTML HUGE
    {'server': 'test-static.com','uri': 'index.html' ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'server': 'test-static.com','uri': 'index.html' ,'port': 80, 'num_connections': 100, 'num_requests': 1000},
    {'server': 'test-static.com','uri': 'index.html' ,'port': 80, 'num_connections': 200, 'num_requests': 2000},
    #Page HTML MEDIUM
    {'server': '127.0.0.1', 'uri':'index.html' ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'server': '127.0.0.1', 'uri':'index.html' ,'port': 80, 'num_connections': 100, 'num_requests': 1000},
    {'server': '127.0.0.1', 'uri':'index.html' ,'port': 80, 'num_connections': 200, 'num_requests': 2000},
    #Page HTML SMALL
    {'server': 'test-ssmall.com', 'uri': 'index.html' ,'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'server': 'test-ssmall.com', 'uri': 'index.html' ,'port': 80, 'num_connections': 100, 'num_requests': 1000},
    {'server': 'test-ssmall.com', 'uri': 'index.html' ,'port': 80, 'num_connections': 200, 'num_requests': 2000},

    #Dynamic site
    {'server': 'test-dynamic.com' , 'uri': '/login_user.php?user_email=anindodas@yahoo.in&user_password=anindo', 'port': 80, 'num_connections': 1, 'num_requests': 1},
    {'server': 'test-dynamic.com' , 'uri': '/login_user.php?user_email=anindodas@yahoo.in&user_password=anindo', 'port': 80, 'num_connections': 100, 'num_requests': 1000},
    {'server': 'test-dynamic.com' , 'uri': '/login_user.php?user_email=anindodas@yahoo.in&user_password=anindo', 'port': 80, 'num_connections': 200, 'num_requests': 2000},

    # Add more test configurations as needed
]

# Function to run httperf and capture the output
def run_httperf(test):
    cmd = [
        'httperf',
        '--server', test['server'],
        '--uri', test['uri'],
        '--port', str(test['port']),
        '--num-conns', str(test['num_connections']),
        '--num-calls', str(test['num_requests']),
        #'--rate', '10'  # Adjust the rate if needed
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

# Function to parse the httperf output and extract relevant metrics
def parse_output(output):
    results = {}
    
    for line in output.splitlines():
        if 'Total:' in line:
            parts = line.split()
            results['total_connections'] = parts[2]
            results['total_requests'] = parts[4]
            results['total_replies'] = parts[6]
            results['total_time'] = parts[8]
        elif 'Connection rate' in line:
            results['connection_rate'] = line.split()[2]
        elif 'Connection time [ms]: min' in line:
            # Capture connection times
            ct = line.split(':')[1].strip().split()
            results['connection_time_min'] = ct[1]
            results['connection_time_avg'] = ct[3]
            results['connection_time_max'] = ct[5]
            results['connection_time_median'] = ct[7]
            results['connection_time_stddev'] = ct[9]
        elif 'Request rate' in line:
            results['request_rate'] = line.split()[2]
        elif 'Request size' in line:
            results['request_size'] = line.split()[3]
        elif 'Reply rate' in line:
            results['reply_rate_min'] = line.split()[4]
            results['reply_rate_avg'] = line.split()[6]
            results['reply_rate_max'] = line.split()[8]
            results['reply_rate_stddev'] = line.split()[10]
        elif 'Reply time' in line:
            results['reply_time'] = line.split()[4]
        elif 'Reply size [B]:' in line:
            reply_size = line.split(':')[1].strip().split()
            results['reply_size_header'] = reply_size[1]
            results['reply_size_content'] = reply_size[3]
            results['reply_size_total'] = reply_size[7].split(')')[0]
        elif 'CPU time [s]:' in line:
            results['cpu_time_user'] = line.split()[4]
            results['cpu_time_system'] = line.split()[6]
        elif 'Net I/O:' in line:
            results['net_io'] = line.split()[2]
        elif 'Errors: total' in line:
            errors = line.split(':')[1].strip().split()
            results['errors_total'] = errors[1]
            results['errors_client_timo'] = errors[3]
            results['errors_socket_timo'] = errors[5]
            results['errors_connrefused'] = errors[7]
            results['errors_connreset'] = errors[9]

    return results

# Run tests and save results to CSV
def run_tests_and_save_to_csv(filename):
    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = [
            'server',
            'uri',
            'port',
            'num_connections',
            'num_requests',
            'total_connections',
            'total_requests',
            'total_replies',
            'total_time',
            'connection_rate',
            'connection_time_min',
            'connection_time_avg',
            'connection_time_max',
            'connection_time_median',
            'connection_time_stddev',
            'request_rate',
            'request_size',
            'reply_rate_min',
            'reply_rate_avg',
            'reply_rate_max',
            'reply_rate_stddev',
            'reply_time',
            'reply_size_header',
            'reply_size_content',
            'reply_size_total',
            'cpu_time_user',
            'cpu_time_system',
            'net_io',
            'errors_total',
            'errors_client_timo',
            'errors_socket_timo',
            'errors_connrefused',
            'errors_connreset',
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for test in TESTS:
            print(f"Running httperf test on {test['server']}:{test['port']}...")
            output = run_httperf(test)
            #print(output)
            metrics = parse_output(output)
            #print(metrics)
            metrics.update(test)  
            writer.writerow(metrics)
            time.sleep(1) 

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <file_name>")
        sys.exit(1)

    file_name = sys.argv[1]
    print(f"File name received: {file_name}")

    run_tests_and_save_to_csv(str(file_name))
    print(f"Tests completed. Results saved to {file_name}.")

