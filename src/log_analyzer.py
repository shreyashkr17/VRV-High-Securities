from collections import Counter

class LogAnalyzer:
    # Here we initialise the log entries with the parsed log entries
    def __init__(self, log_entries):
        """Initialize with parsed log entries."""
        self.log_entries = log_entries

    # Here we count the requests per ip_address and return the count in the form of a dictioanry or a list in sorted manner
    def count_requests_per_ip(self, as_dict=False):
        counts = Counter(entry['ip_address'] for entry in self.log_entries)
        return counts if as_dict else counts.most_common()

    # Here we count the endpoint access and return the count in the form of a dictionary or a list in sorted manner
    def count_endpoint_access(self, as_dict=False):
        counts = Counter(entry['endpoint'] for entry in self.log_entries)
        return counts if as_dict else counts.most_common()

    # Here we detect the sucpicious activity in the log entries and return the count in the form of a dictionary or a list in sorted manner, 
    # it will return only if the count is greater than the threshold value  
    def detect_suspicious_activity(self, threshold=10, as_dict=False):
        failed_logins = Counter(
            entry['ip_address'] for entry in self.log_entries
            if entry['status_code'] == '401' or 'Invalid credentials' in str(entry['additional_info'])
        )
        if as_dict:
            return {ip: count for ip, count in failed_logins.items() if count >= threshold}
        return [(ip, count) for ip, count in failed_logins.items() if count >= threshold]
