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
        
        instru_file_name = f"{file_name}_instru"
        instru_file_path = os.path.join(dir_path, instru_file_name)
        copy_file_name = f"{file_name}_copy"
        copy_file_path = os.path.join(dir_path, copy_file_name)
        
        try:
            # Copy the file
            shutil.copy(file_path, instru_file_path)
            print(f"Copied: {file_path} to {instru_file_path}\n")

            shutil.copy(copy_file_path,file_path)
            print(f"Copied: {copy_file_path} to {file_path}\n")

        except Exception as e:
            print(f"Error copying file {file_path}: {e}")

    print(f"{file_path} revert complete\n")


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