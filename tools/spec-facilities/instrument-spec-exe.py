import os
import sys
import shutil

def copy_file_and_create_instru(file_path):
    # Check if the provided path is a directory
    if not os.path.isdir(dir_path):
        print(f"The path {dir_path} is not a valid directory.")
        return
    print(f'STARTING FOR {file_path}\n')

    # Iterate over all files in the directory
    for file_name in os.listdir(dir_path):
        # Get the full file path
        file_path = os.path.join(dir_path, file_name)
        
        # Skip directories
        if os.path.isdir(file_path) or '_copy' in file_name or '_instru' in file_name:
            continue
        
        # Create a new filename with '_copy' appended before the extension
        new_file_name = f"{file_name}_copy"
        new_file_path = os.path.join(dir_path, new_file_name)
        
        try:
            # Copy the file
            shutil.copy(file_path, new_file_path)
            print(f"Copied: {file_path} to {new_file_path}\n")
        except Exception as e:
            print(f"Error copying file {file_path}: {e}")

        print(f"{new_file_path} copy complete\n")
         # Create bash instrumentation
        with open(file_path, 'w') as file:
            # Write the shebang line
            file.write('#!/usr/bin/bash\n')
            
            # Write the f-string on the second line
            file.write(f'/usr/sbin/Kss_loader /home/user/ghidra_auto/analysis_results/{file_name}_ 100 {new_file_path} $@')

            #print(f'Second line : /usr/sbin/Kss_loader /home/user/Desktop/ghidra_auto/analysis_results/{file_name}_ {new_file_path} $@ \n')
            print(f"{file_path} Rewrite complete\n")
            print("\n")
    

if __name__ == "__main__":
    # Ensure the script receives exactly one argument (the file path)
    if len(sys.argv) < 2:
        print("Usage: python script.py <bench1> <bench2> ... <benchN>")
        sys.exit(1)
    
    cost_dir_path = '/home/user/spec_cpu/benchspec/CPU'
    cost_exe = 'exe'

    for bench in sys.argv[1:]:
        dir_path = os.path.join(cost_dir_path,bench,cost_exe)
        copy_file_and_create_instru(dir_path)
