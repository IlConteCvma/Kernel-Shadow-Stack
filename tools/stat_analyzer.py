import pandas as pd
import sys


def parse_csv_and_generate_statistics(file_path):
    # Read the CSV file into a pandas DataFrame
    df = pd.read_csv(file_path)
    
    # Ensure the data types are correct
    df['pid'] = df['pid'].astype(int)
    df['type'] = df['type'].astype(int)
    df['timestamp'] = df['timestamp'].astype(int)

    # 1) Number of type = 0
    count_type_0 = df[df['type'] == 0].shape[0]
    
    # 2) Number of type = 1
    count_type_1 = df[df['type'] == 1].shape[0]
    
    # 3) Group by timestamp (converted to seconds) and count lines per second
    df['timestamp_sec'] = df['timestamp'] // 1_000_000_000  # Convert from nanoseconds to seconds
    count_per_second = df.groupby('timestamp_sec').size()

    # Return the statistics
    return {
        "count_type_0": count_type_0,
        "count_type_1": count_type_1,
        "count_per_second": count_per_second
    }


if __name__ == "__main__":
    # Ensure the script receives exactly one argument (the file path)
    if len(sys.argv) < 2:
        print("Usage: python script.py <dir_path1> <dir_path2> ... <dir_pathN>")
        sys.exit(1)
    file_path = sys.argv[1]  # Get the file path from the first command-line argument

    
    try:
        stats = parse_csv_and_generate_statistics(file_path)
        
        print("Statistics:")
        print(f"Count of type = 0: {stats['count_type_0']}")
        print(f"Count of type = 1: {stats['count_type_1']}")
        
        print("\nCount of rows per second:")
        for timestamp, count in stats['count_per_second'].items():
            print(f"Timestamp {timestamp} sec: {count} rows")
    
    except Exception as e:
        print(f"Error reading the file: {e}")