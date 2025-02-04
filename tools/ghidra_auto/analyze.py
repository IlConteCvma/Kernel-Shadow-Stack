import subprocess
import argparse
import os

# DEBUG
PRINT_GHIDRA_OUTPUT=True

# GHIDRA VARS
GHIDRA_FOLDER="/home/user/ghidra_11"
GHIDRA_BINARY= os.path.join(GHIDRA_FOLDER, "support/analyzeHeadless")
GHIDRA_OUTPUT_PROJECT_FOLDER = "/home/user/Desktop/ghidra_auto/ghidra_projects"
GHIDRA_SCRIPT= "/home/user/ghidra_11/Ghidra/Debug/Debugger/ghidra_scripts/GetRetCallWithLabel.java"

CMD_FORMAT = [GHIDRA_BINARY, GHIDRA_OUTPUT_PROJECT_FOLDER, "REPLACE_NAME" , "-import", "REPLACE_PATH", "-postScript", GHIDRA_SCRIPT]


def execute(cmd):
    popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    for stdout_line in iter(popen.stdout.readline, ""):
        yield stdout_line 
    popen.stdout.close()
    return_code = popen.wait()
    if return_code:
        raise subprocess.CalledProcessError(return_code, cmd)

def valid_path(string):
    if os.path.exists(string):
        return string
    else:
        raise argparse.ArgumentTypeError(f"{string}: No such file or directory")


def prepare_cmd(path):

    formatted_cmd = CMD_FORMAT.copy()
    for i in range(len(CMD_FORMAT)):
        if CMD_FORMAT[i] == "REPLACE_NAME":
            formatted_cmd[i] = os.path.basename(path)
        elif CMD_FORMAT[i] == "REPLACE_PATH":
            formatted_cmd[i] = path
    
    return formatted_cmd

# get args
parser = argparse.ArgumentParser(
                    prog='CallRetAnalyzer',
                    description='Run Ghidra analysis from command line')

parser.add_argument("-p", "--path", help="directory or file to analyze", type=valid_path, required=True)

args = parser.parse_args()

#check if folder or file
if os.path.isfile(args.path):

    print(f"[+] Running analysis on: {args.path}\n") 
    # run cmd for file
    for output in execute(prepare_cmd(args.path)):
        if PRINT_GHIDRA_OUTPUT:
            print(output)

else:

    print(f"[+] Analyzing directory {args.path}\n")
    
    directory = os.fsencode(args.path)
        
    for file in os.listdir(directory):
        filename = os.fsdecode(file)
        full_path = os.path.join(directory, file)
        if os.path.isfile(full_path): 
            # print(os.path.join(directory, file))

            print(f"[+] Running analysis on: {full_path}\n") 
            # print(prepare_cmd(full_path))
            # run cmd for file
            for output in execute(prepare_cmd(full_path)):
                if PRINT_GHIDRA_OUTPUT:
                    print(output)




