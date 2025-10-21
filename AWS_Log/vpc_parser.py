import os
import re
import gzip
import csv
import sys
from typing import List, Dict, Any
from datetime import datetime, timedelta, timezone
from multiprocessing import Pool, cpu_count
import multiprocessing
from tqdm import tqdm

# Windows encoding issue resolution
if sys.platform.startswith('win'):
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
    try:
        import locale
        locale.setlocale(locale.LC_ALL, 'ko_KR.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'Korean_Korea.949')
        except:
            pass


class VPCFlowLogParser:
    def __init__(self):
        self.parsed_data = []

    def convert_unix_to_windows_format(self, unix_timestamp: str) -> str:
        """Convert Unix timestamp to Windows Start/End format (UTC+0)"""
        try:
            if not unix_timestamp or not unix_timestamp.isdigit():
                return unix_timestamp
            
            dt_obj_utc = datetime.fromtimestamp(int(unix_timestamp), tz=timezone.utc)
            # Windows Start/End format: YYYY-MM-DD HH:MM:SS (UTC+0)
            return dt_obj_utc.strftime('%Y-%m-%d %H:%M:%S (UTC+0)')
        except Exception as e:
            print(f"Unix timestamp conversion error ({unix_timestamp}): {e}")
            return unix_timestamp

    def parse_log_line(self, line: str, source_file: str) -> Dict[str, Any]:
        """Parse single VPC Flow Log line"""
        # VPC Flow Log standard field order
        # version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes window-start window-end action flow-log-status
        # https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-fields
        
        # Split by space (VPC Flow Log is space-separated)
        parts = line.strip().split()
        
        # Skip header lines or insufficient fields
        if len(parts) < 13 or parts[0] in ['version', 'start', 'end'] or parts[10] in ['start', 'end']:
            return None
        
        try:
            # Convert Unix timestamp to Windows Start/End format (UTC+0)
            window_start_iso = self.convert_unix_to_windows_format(parts[10])
            window_end_iso = self.convert_unix_to_windows_format(parts[11])
            
            parsed_event = {
                'version': parts[0],
                'account_id': parts[1],
                'interface_id': parts[2],
                'srcaddr': parts[3],
                'dstaddr': parts[4],
                'srcport': parts[5],
                'dstport': parts[6],
                'protocol': parts[7],
                'packets': parts[8],
                'bytes': parts[9],
                'window_start_(UTC+0)': window_start_iso.replace(' (UTC+0)', ''),
                'window_end_(UTC+0)': window_end_iso.replace(' (UTC+0)', ''),
                'action': parts[12],
                'flow_log_status': parts[13] if len(parts) > 13 else '',
                'sourceFile': os.path.basename(source_file)
            }
            
            return parsed_event
            
        except Exception as e:
            print(f"VPC log parsing error: {e}")
            return None

    def parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse VPC Flow Log file and convert to structured data"""
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
            print(f"File reading error: {e}")
        
        return parsed_events

    def parse_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """Parse all VPC Flow Log files in specified directory (multiprocessing)"""
        log_files = []
        
        # Find log files
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                # Check VPC Flow Log file pattern
                if (file.lower().endswith(('.log', '.txt', '.gz')) or 
                    re.match(r'\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-[A-F0-9]+', file)):
                    log_files.append(os.path.join(root, file))
        
        if not log_files:
            return []

        # Parse files with multiprocessing
        num_processes = min(cpu_count(), len(log_files))
        
        with Pool(processes=num_processes) as pool:
            # Use tqdm for progress bar
            results = list(tqdm(
                pool.imap(self._parse_single_file, log_files),
                total=len(log_files),
                desc="Parsing VPC Flow Log files",
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
            print("No data to save.")
            return
        
        # Collect all column names
        all_columns = set()
        for event in events:
            all_columns.update(event.keys())

        # Define column order (main columns first)
        priority_columns = [
            'window_start_(UTC+0)', 'window_end_(UTC+0)',
            'srcaddr', 'dstaddr', 'srcport', 'dstport', 'protocol', 'action',
            'packets', 'bytes', 'interface_id', 'account_id', 'version',
            'flow_log_status'
        ]
        
        ordered_columns = []
        for col in priority_columns:
            if col in all_columns:
                ordered_columns.append(col)
                all_columns.remove(col)
        
        # Remove sourceFile from all_columns so it's not included in remaining_columns
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
                    # Set default empty string for all fields
                    row = {}
                    for col in ordered_columns:
                        row[col] = event.get(col, '')
                    writer.writerow(row)
            
        except Exception as e:
            print(f"CSV save error: {e}")


def main():
    """Main execution function"""
    parser = VPCFlowLogParser()
    
    print("AWS VPC Flow Log Parser")
    print("=" * 50)
    
    # Set input directory
    input_directory = r"C:\Users\kelly.jang\Desktop\새 폴더\AWS_LOG\VPC Flow Log (S3)"
    
    # Generate output filename with current time
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"vpc_flow_log_{current_time}.csv"
    
    print(f"Input directory: {input_directory}")
    print(f"Output file: {output_file}")
    
    # Parse logs
    print(f"\nParsing log files from directory: {input_directory}")
    events = parser.parse_directory(input_directory)
    
    if events:
        # Save to CSV
        parser.save_to_csv(events, output_file)
        print(f"\nParsing completed!")
    else:
        print("No data parsed.")


if __name__ == "__main__":
    main()
