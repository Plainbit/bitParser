# -*- coding: utf-8 -*-
import os
import re
import gzip
import csv
import sys
from datetime import datetime, timedelta
from multiprocessing import Pool, cpu_count
import multiprocessing
from typing import List, Dict, Any
from tqdm import tqdm

# Windows Korean encoding issue resolution
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')

class S3AccessLogParser:
    def __init__(self):
        self.parsed_data = []

    def _convert_s3_timestamp(self, timestamp_str):
        """Convert S3 timestamp to YYYY-MM-DD hh:mm:ss format"""
        try:
            import re
            # Parse S3 Access Log timestamp format using regex: [01/Oct/2025:11:55:11 +0000]
            pattern = r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})\]'
            match = re.match(pattern, str(timestamp_str))
            
            if match:
                day, month, year, hour, minute, second, tz_offset = match.groups()
                
                # Convert month name to number
                month_map = {
                    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
                }
                month_num = month_map.get(month, '01')
                
                # Return in YYYY-MM-DD hh:mm:ss format
                return f"{year}-{month_num}-{day} {hour}:{minute}:{second}"
            else:
                return timestamp_str
        except Exception as e:
            print(f"S3 timestamp conversion error ({timestamp_str}): {e}")
            return timestamp_str
    
    def _extract_timezone(self, timestamp_str):
        """Extract timezone information from S3 timestamp"""
        try:
            import re
            # Extract timezone info using regex: [01/Oct/2025:11:55:11 +0000]
            pattern = r'\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})\]'
            match = re.match(pattern, str(timestamp_str))
            
            if match:
                day, month, year, hour, minute, second, tz_offset = match.groups()
                return tz_offset
            else:
                return '+0000'  # Default value
        except Exception as e:
            print(f"S3 timezone extraction error ({timestamp_str}): {e}")
            return '+0000'

    def parse_log_line(self, line: str, source_file: str) -> Dict[str, Any]:
        """Parse single S3 Access Log line"""
        # S3 Access Log has quoted strings, so parse using regex
        
        # Regex pattern: handle both quoted strings and space-separated fields
        # Pattern: (field1) (field2) [time] (IP) (requester) (request_id) (operation) (key) "(request_uri)" (status) (error) (bytes) (size) (time1) (time2) "(referer)" "(user_agent)" (version) (host_id) (sig_ver) (cipher) (auth_type) (host_header) (tls_ver) (dash1) (dash2)
        
        # More accurate regex pattern
        pattern = r'^(\S+)\s+(\S+)\s+(\[[^\]]+\])\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(".*?")\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(".*?")\s+(".*?")\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$'
        
        match = re.match(pattern, line)
        
        if not match:
            # Try simple parsing if regex fails
            return self._parse_simple(line, source_file)
        
        # Fields extracted by regex
        fields = match.groups()
        
        parsed_event = {
            'bucket_owner': fields[0],
            'bucket': fields[1],
            'original_timestamp': fields[2],
            'request_datetime_(UTC+0)': self._convert_s3_timestamp(fields[2]),
            'remote_ip': fields[3],
            'requester': fields[4],
            'request_id': fields[5],
            'operation': fields[6],
            'key': fields[7],
            'request_uri': fields[8].strip('"'),
            'http_status_code': fields[9],
            'error_code': fields[10],
            'bytes_sent': fields[11],
            'object_size': fields[12],
            'total_time': fields[13],
            'turn_around_time': fields[14],
            'referer': fields[15].strip('"'),
            'user_agent': fields[16].strip('"'),
            'version_id': fields[17],
            'host_id': fields[18],
            'signature_version': fields[19],
            'cipher_suite': fields[20],
            'authentication_type': fields[21],
            'host_header': fields[22],
            'tls_version': fields[23],
            'dash1': fields[24],
            'dash2': fields[25],
            'sourceFile': os.path.basename(source_file)
        }
        
        # Try to extract awsRegion from request_datetime
        # Remove local time addition (use UTC time as-is)
        
        return parsed_event

    def _parse_simple(self, line: str, source_file: str) -> Dict[str, Any]:
        """Simple parsing method (when regex fails)"""
        # Split by space, but treat quoted content as one field
        parts = []
        current_part = ""
        in_quotes = False
        
        for char in line:
            if char == '"' and not in_quotes:
                in_quotes = True
                current_part += char
            elif char == '"' and in_quotes:
                in_quotes = False
                current_part += char
            elif char == ' ' and not in_quotes:
                if current_part:
                    parts.append(current_part)
                    current_part = ""
            else:
                current_part += char
        
        if current_part:
            parts.append(current_part)
        
        # Extract minimum fields only
        parsed_event = {
            'bucket_owner': parts[0] if len(parts) > 0 else '',
            'bucket': parts[1] if len(parts) > 1 else '',
            'original_timestamp': parts[2] if len(parts) > 2 else '',
            'request_datetime_(UTC+0)': self._convert_s3_timestamp(parts[2]) if len(parts) > 2 else '',
            'remote_ip': parts[3] if len(parts) > 3 else '',
            'requester': parts[4] if len(parts) > 4 else '',
            'request_id': parts[5] if len(parts) > 5 else '',
            'operation': parts[6] if len(parts) > 6 else '',
            'key': parts[7] if len(parts) > 7 else '',
            'request_uri': parts[8].strip('"') if len(parts) > 8 else '',
            'http_status_code': parts[9] if len(parts) > 9 else '',
            'error_code': parts[10] if len(parts) > 10 else '',
            'bytes_sent': parts[11] if len(parts) > 11 else '',
            'object_size': parts[12] if len(parts) > 12 else '',
            'total_time': parts[13] if len(parts) > 13 else '',
            'turn_around_time': parts[14] if len(parts) > 14 else '',
            'referer': parts[15].strip('"') if len(parts) > 15 else '',
            'user_agent': parts[16].strip('"') if len(parts) > 16 else '',
            'version_id': parts[17] if len(parts) > 17 else '',
            'sourceFile': os.path.basename(source_file)
        }
        
        # Remove local time addition (use UTC time as-is)
        
        return parsed_event

    def parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse S3 Access Log file and convert to structured data"""
        parsed_events = []
        
        try:
            if file_path.lower().endswith('.gz'):
                file_handle = gzip.open(file_path, 'rt', encoding='utf-8')
            else:
                file_handle = open(file_path, 'r', encoding='utf-8')
            
            with file_handle as file:
                for line in file:
                    line = line.strip()
                    if not line or line.startswith('#'):  # Skip comment lines
                        continue
                    
                    parsed_event = self.parse_log_line(line, file_path)
                    if parsed_event:
                        parsed_events.append(parsed_event)
                        
        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"File read error: {e}")
        
        return parsed_events

    def parse_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """Parse all S3 Access Log files in specified directory (multiprocessing)"""
        log_files = []

        for root, _, files in os.walk(directory_path):
            for file in files:
                # Check S3 Access Log file pattern (date format without extension)
                if (file.lower().endswith(('.log', '.txt', '.gz')) or 
                    re.match(r'\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-[A-F0-9]+', file)):
                    log_files.append(os.path.join(root, file))

        if not log_files:
            return []

        # Parse files using multiprocessing
        num_processes = min(cpu_count(), len(log_files))

        with Pool(processes=num_processes) as pool:
            # Use tqdm for progress bar
            results = list(tqdm(
                pool.imap(self._parse_single_file, log_files),
                total=len(log_files),
                desc="Parsing S3 Access Log files",
                unit="file"
            ))

        # Combine results
        all_events = []
        for file_path, events in zip(log_files, results):
            all_events.extend(events)

        return all_events

    def _parse_single_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Helper function to parse single file (for multiprocessing)"""
        try:
            return self.parse_log_file(file_path)
        except Exception as e:
            print(f"File parsing error ({file_path}): {e}")
            return []

    def save_to_csv(self, events: List[Dict[str, Any]], output_file: str):
        """Save parsed events to CSV file"""
        if not events:
            print("No events to save.")
            return

        # Collect all column names
        all_columns = set()
        for event in events:
            all_columns.update(event.keys())

        # Define column order (important columns first)
        priority_columns = [
            'original_timestamp', 'request_datetime_(UTC+0)', 'remote_ip', 'operation', 'request_uri',
            'http_status_code', 'bytes_sent', 'object_size', 'user_agent', 'requester',
            'bucket_owner', 'bucket', 'request_id', 'key', 'error_code',
            'total_time', 'turn_around_time', 'referer', 'version_id'
        ]
        
        ordered_columns = []
        for col in priority_columns:
            if col in all_columns:
                ordered_columns.append(col)
                all_columns.remove(col)
        
        # Remove sourceFile from all_columns to ensure it's not in remaining_columns
        source_file_removed = False
        if 'sourceFile' in all_columns:
            all_columns.remove('sourceFile')
            source_file_removed = True
        
        # Add remaining columns in alphabetical order
        remaining_columns = sorted(all_columns)
        ordered_columns.extend(remaining_columns)
        
        # Add sourceFile at the end
        if source_file_removed:
            ordered_columns.append('sourceFile')

        try:
            with open(output_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=ordered_columns)
                writer.writeheader()
                
                # Use tqdm for progress bar when writing CSV
                for event in tqdm(events, desc="Writing CSV", unit="event"):
                    writer.writerow(event)
        except Exception as e:
            print(f"CSV file save error: {e}")

def main():
    """Main execution function"""
    # Create result folder structure
    result_dir = "result"
    parse_log_dir = os.path.join(result_dir, "parse_log")
    os.makedirs(parse_log_dir, exist_ok=True)
    
    parser = S3AccessLogParser()
    
    print("AWS S3 Server Access Log Parser (Modified Version)")
    print("=" * 50)
    
    # Set input directory
    input_directory = "C:/Users/kelly.jang/Desktop/새 폴더/AWS_LOG/S3 Server Access Log (S3)"
    
    # Generate output filename with current time (save in result/parse_log folder)
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(parse_log_dir, f"s3_access_log_{current_time}.csv")
    
    print(f"Input directory: {input_directory}")
    print(f"Output file: {output_file}")
    
    # Parse logs
    print(f"\nParsing log files in directory: {input_directory}")
    events = parser.parse_directory(input_directory)
    
    if events:
        print(f"\nTotal parsed events: {len(events)}")
        parser.save_to_csv(events, output_file)
    else:
        print("No parsed data available.")

if __name__ == "__main__":
    main()
