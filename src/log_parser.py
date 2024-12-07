import re

class LogParser:
    @staticmethod
    def parse_log_line(line):
        # This regex function is used to parse the log line and extract the IP address (e.g. 123.234.0.1), request type (e.g. GET)
        # endpoint (e.g. /home), status code (e.g. 200, 401, 404) and additional Infor (e.g. Invalid credentials)
        pattern = r'^(\d+\.\d+\.\d+\.\d+) .* "([A-Z]+) (/\S*) HTTP/\d\.\d" (\d+) \d+ ?(.*)?$'
        match = re.match(pattern, line.strip())
        if match:
            return {
                'ip_address': match.group(1),
                'request_type': match.group(2),
                'endpoint': match.group(3),
                'status_code': match.group(4),
                'additional_info': match.group(5)
            }
        return {}

    @staticmethod
    def parse_log_lines(lines):
        # This function is used to parse the log lines and extract the log line using the parse_log_line function
        return [LogParser.parse_log_line(line) for line in lines if LogParser.parse_log_line(line)]
