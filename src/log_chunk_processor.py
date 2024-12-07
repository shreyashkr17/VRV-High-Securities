import csv
from src.log_analyzer import LogAnalyzer
from src.log_parser import LogParser

def process_log_in_chunks(log_file_path, output_file_path, chunk_size=2000):
    """
    Process the log file in chunks and aggregate results.

    :param log_file_path: Path to the log file.
    :param output_file_path: Path to save the CSV file.
    :param chunk_size: Number of lines to process at a time.
    """
    ip_request_counts = {}
    endpoint_counts = {}
    suspicious_ips = {}

    # This function updates the counter when we encounter new data in the sample.log file 
    # and if the data is already present in the counter then it increments the value of the key by the new value
    def update_counter(counter, new_data):
        for key, value in new_data.items():
            counter[key] = counter.get(key, 0) + value

    try:
        # Here we open the sample.log file and read it line by line in chunks of 2000 lines in each iteration 
        # and then parse the log lines according to ip_address request type, endpoint count according to the sorted manner and the suspicious ip_address
        # and then save the results to the output file
        with open(log_file_path, 'r') as log_file:
            chunk = []
            for line in log_file:
                chunk.append(line)
                if len(chunk) == chunk_size:
                    parsed_entries = LogParser.parse_log_lines(chunk)
                    analyzer = LogAnalyzer(parsed_entries)
                    update_counter(ip_request_counts, analyzer.count_requests_per_ip(as_dict=True))
                    update_counter(endpoint_counts, analyzer.count_endpoint_access(as_dict=True))
                    update_counter(suspicious_ips, analyzer.detect_suspicious_activity(as_dict=True))
                    chunk = []

            if chunk:
                parsed_entries = LogParser.parse_log_lines(chunk)
                analyzer = LogAnalyzer(parsed_entries)
                update_counter(ip_request_counts, analyzer.count_requests_per_ip(as_dict=True))
                update_counter(endpoint_counts, analyzer.count_endpoint_access(as_dict=True))
                update_counter(suspicious_ips, analyzer.detect_suspicious_activity(as_dict=True))

        save_results_to_csv(output_file_path, ip_request_counts, endpoint_counts, suspicious_ips)

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
    except Exception as e:
        print(f"Error processing log file: {e}")

def save_results_to_csv(output_file_path, ip_request_counts, endpoint_counts, suspicious_ips):
    """
    Save the aggregated results to a CSV file.
    """
    # Here we save the result to the output file in the form of a csv format with the header as Requests per IP address
    # and then the ip_address and the request count in thhe sorted  manner
    # then we save the most accessed endpoints in the form of a csv format with the header as Most Accessed Endpoints
    # and then the endpoint and the access count in the sorted manner
    # then we save the suspicious activity in the form of a csv format with the header as Suspicious Activity
    # and then the ip_address and the filed login attempts or having 401 status code in the sorted manner
    with open(output_file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        # this is the header of the Request per IP in CSV file and data is wriiten for ip_address and request count in the sorted manner
        csv_writer.writerow(['Requests per IP'])
        csv_writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_request_counts.items(), key=lambda x: x[1], reverse=True):
            csv_writer.writerow([ip, count])
        csv_writer.writerow([])

        #this is the header of the Most Accessed Endpoints in CSV file and data is wriiten for endpoint and access count in the sorted manner
        csv_writer.writerow(['Most Accessed Endpoints'])
        csv_writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True):
            csv_writer.writerow([endpoint, count])
        csv_writer.writerow([])

        # this is the header of the Suspicious Activity in CSV file and data is wriiten for ip_address and filed login attempts in the sorted manner
        csv_writer.writerow(['Suspicious Activity'])
        csv_writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            csv_writer.writerow([ip, count])
