import os
from src.log_chunk_processor import process_log_in_chunks

def main():
    # this is the main access point where we initialise the log file path and the output file path with proper file names
    # and then we call the process_log_in chunks function to process the log file in chunks
    # and then we create & print the results to the output file
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    output_dir = os.path.join(os.path.dirname(__file__), 'output')
    log_file_path = os.path.join(logs_dir, 'sample.log')
    output_file_path = os.path.join(output_dir, 'log_analysis_result.csv')
    os.makedirs(output_dir, exist_ok=True)

    print("Analyzing log file in chunks...")
    # we are taking the chunk size as 2000 lines in each iteration to process the sample.log file.
    process_log_in_chunks(log_file_path, output_file_path, chunk_size=2000)
    print(f"\nResults saved to {output_file_path}")

if __name__ == "__main__":
    main()
