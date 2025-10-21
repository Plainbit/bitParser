import json
import csv
import os
import gzip
import sys
from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from multiprocessing import Pool, cpu_count
import multiprocessing
from tqdm import tqdm

# Windows encoding issue resolution
if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')


class CloudTrailParser:
    def __init__(self):
        self.parsed_data = []
        
        # AWS region UTC offset (hours)
        self.region_timezone_offsets = {
            'us-east-1': -5,      # Eastern Time (EST/EDT)
            'us-east-2': -5,      # Eastern Time (EST/EDT)
            'us-west-1': -8,      # Pacific Time (PST/PDT)
            'us-west-2': -8,      # Pacific Time (PST/PDT)
            'ap-northeast-1': 9,  # Japan Standard Time
            'ap-northeast-2': 9,  # Korea Standard Time
            'ap-northeast-3': 9,  # Japan Standard Time
            'ap-southeast-1': 8,  # Singapore Time
            'ap-southeast-2': 10, # Australian Eastern Time
            'ap-southeast-3': 7,  # Western Indonesia Time
            'ap-south-1': 5.5,    # India Standard Time
            'ca-central-1': -5,   # Eastern Time (EST/EDT)
            'eu-central-1': 1,    # Central European Time
            'eu-west-1': 0,       # Greenwich Mean Time
            'eu-west-2': 0,       # Greenwich Mean Time
            'eu-west-3': 1,       # Central European Time
            'eu-north-1': 1,      # Central European Time
            'sa-east-1': -3,      # Brasilia Time
        }
    
    def convert_to_region_time(self, event_time: str, aws_region: str) -> str:
        """Convert eventTime to local time of the region"""
        try:
            # Parse as UTC time
            utc_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            
            # Get region offset
            offset_hours = self.region_timezone_offsets.get(aws_region, 0)
            
            # Convert to local time
            local_time = utc_time + timedelta(hours=offset_hours)
            
            # Return in ISO format
            return local_time.strftime('%Y-%m-%dT%H:%M:%S')
        except Exception as e:
            print(f"Time conversion error: {e}")
            return event_time  # Return original if conversion fails
    
    def parse_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse CloudTrail log file and convert to structured data"""
        parsed_events = []
        
        try:
            # Open file with appropriate method based on extension
            if file_path.lower().endswith('.gz'):
                file_handle = gzip.open(file_path, 'rt', encoding='utf-8')
            else:
                file_handle = open(file_path, 'r', encoding='utf-8')
            
            with file_handle as file:
                content = file.read().strip()
                
                if not content:
                    print(f"Empty file: {file_path}")
                    return parsed_events
                
                
                try:
                    # Try JSON parsing
                    data = json.loads(content)
                    
                    # Check CloudTrail format
                    if isinstance(data, dict) and 'Records' in data:
                        # CloudTrail format: {"Records": [...]}
                        events = data['Records']
                        if isinstance(events, list):
                            for event in events:
                                parsed_event = self._parse_single_event(event, file_path)
                                if parsed_event:
                                    parsed_events.append(parsed_event)
                    elif isinstance(data, list):
                        # Array format JSON
                        for event in data:
                            parsed_event = self._parse_single_event(event, file_path)
                            if parsed_event:
                                parsed_events.append(parsed_event)
                    else:
                        # Single JSON object
                        parsed_event = self._parse_single_event(data, file_path)
                        if parsed_event:
                            parsed_events.append(parsed_event)
                            
                except json.JSONDecodeError as e:
                    print(f"JSON parsing error (file: {file_path}): {e}")
                    # Try JSON Lines format
                    lines = content.split('\n')
                    for line_num, line in enumerate(lines, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                            parsed_event = self._parse_single_event(event, file_path)
                            if parsed_event:
                                parsed_events.append(parsed_event)
                        except json.JSONDecodeError as line_e:
                            print(f"Line {line_num} JSON parsing error: {line_e}")
                            continue
                        
        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"File reading error: {e}")
        
        return parsed_events
    
    def _parse_single_event(self, event: Dict[str, Any], source_file: str) -> Dict[str, Any]:
        """Parse single CloudTrail event"""
        parsed_event = {}
        
        # Basic fields
        parsed_event['eventTime'] = event.get('eventTime', '')
        parsed_event['awsRegion'] = event.get('awsRegion', '')
        parsed_event['eventName'] = event.get('eventName', '')
        parsed_event['eventSource'] = event.get('eventSource', '')
        
        # Add region-specific local time
        event_time = event.get('eventTime', '')
        aws_region = event.get('awsRegion', '')
        if event_time and aws_region:
            local_time = self.convert_to_region_time(event_time, aws_region)
            # Remove T from eventTimeLocal format
            parsed_event['eventTimeLocal'] = local_time.replace('T', ' ') if local_time else ''
        else:
            parsed_event['eventTimeLocal'] = ''
        parsed_event['sourceIpAddress'] = event.get('sourceIPAddress', '')
        parsed_event['userAgent'] = event.get('userAgent', '')
        parsed_event['sourceFile'] = os.path.basename(source_file)
        
        # Process userIdentity - separate all sub-keys into columns
        user_identity = event.get('userIdentity', {})
        if user_identity:
            for key, value in user_identity.items():
                if isinstance(value, (dict, list)):
                    # Convert nested objects or arrays to JSON string
                    parsed_event[f'userIdentity.{key}'] = json.dumps(value, ensure_ascii=False)
                else:
                    parsed_event[f'userIdentity.{key}'] = str(value) if value is not None else ''
        else:
            # Fill with empty values if userIdentity is missing
            parsed_event['userIdentity.type'] = ''
            parsed_event['userIdentity.principalId'] = ''
            parsed_event['userIdentity.arn'] = ''
            parsed_event['userIdentity.accountId'] = ''
            parsed_event['userIdentity.userName'] = ''
        
        # Process requestElements - save as raw JSON
        request_elements = event.get('requestParameters', {})
        parsed_event['requestElements'] = json.dumps(request_elements, ensure_ascii=False) if request_elements else ''
        
        # Process responseElements - save as raw JSON
        response_elements = event.get('responseElements', {})
        parsed_event['responseElements'] = json.dumps(response_elements, ensure_ascii=False) if response_elements else ''
        
        # Additional useful fields
        parsed_event['eventType'] = event.get('eventType', '')
        parsed_event['eventID'] = event.get('eventID', '')
        parsed_event['errorCode'] = event.get('errorCode', '')
        parsed_event['errorMessage'] = event.get('errorMessage', '')
        parsed_event['requestID'] = event.get('requestID', '')
        parsed_event['eventCategory'] = event.get('eventCategory', '')
        parsed_event['readOnly'] = event.get('readOnly', '')
        parsed_event['resources'] = json.dumps(event.get('resources', []), ensure_ascii=False) if event.get('resources') else ''
        parsed_event['serviceEventDetails'] = json.dumps(event.get('serviceEventDetails', {}), ensure_ascii=False) if event.get('serviceEventDetails') else ''
        parsed_event['additionalEventData'] = json.dumps(event.get('additionalEventData', {}), ensure_ascii=False) if event.get('additionalEventData') else ''
        parsed_event['apiVersion'] = event.get('apiVersion', '')
        parsed_event['managementEvent'] = event.get('managementEvent', '')
        parsed_event['insightDetails'] = json.dumps(event.get('insightDetails', {}), ensure_ascii=False) if event.get('insightDetails') else ''
        parsed_event['recipientAccountId'] = event.get('recipientAccountId', '')
        parsed_event['sessionCredentialDurationSeconds'] = event.get('sessionCredentialDurationSeconds', '')
        parsed_event['sessionIssuer'] = json.dumps(event.get('sessionIssuer', {}), ensure_ascii=False) if event.get('sessionIssuer') else ''
        parsed_event['sessionMfaAuthenticated'] = event.get('sessionMfaAuthenticated', '')
        parsed_event['sessionContext'] = json.dumps(event.get('sessionContext', {}), ensure_ascii=False) if event.get('sessionContext') else ''
        parsed_event['tlsDetails'] = json.dumps(event.get('tlsDetails', {}), ensure_ascii=False) if event.get('tlsDetails') else ''
        parsed_event['vpcEndpointId'] = event.get('vpcEndpointId', '')
        parsed_event['addendum'] = json.dumps(event.get('addendum', {}), ensure_ascii=False) if event.get('addendum') else ''
        parsed_event['edgeDeviceDetails'] = json.dumps(event.get('edgeDeviceDetails', {}), ensure_ascii=False) if event.get('edgeDeviceDetails') else ''
        parsed_event['eventVersion'] = event.get('eventVersion', '')
        parsed_event['userIdentity.sessionContext'] = json.dumps(user_identity.get('sessionContext', {}), ensure_ascii=False) if user_identity.get('sessionContext') else ''
        
        return parsed_event
    
    def parse_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """Parse all CloudTrail log files in directory (multiprocessing)"""
        if not os.path.exists(directory_path):
            print(f"Directory not found: {directory_path}")
            return []
        
        # Find JSON files (including compressed files)
        json_files = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.lower().endswith(('.json', '.jsonl', '.json.gz')):
                    json_files.append(os.path.join(root, file))
        
        if not json_files:
            return []
        
        # File parsing with multiprocessing
        num_processes = min(cpu_count(), len(json_files))
        
        with Pool(processes=num_processes) as pool:
            # Use tqdm for progress bar
            results = list(tqdm(
                pool.imap(self._parse_single_file, json_files),
                total=len(json_files),
                desc="Parsing CloudTrail log files",
                unit="file"
            ))
        
        # Combine results
        all_events = []
        for file_path, events in zip(json_files, results):
            all_events.extend(events)
        
        return all_events
    
    def _parse_single_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Helper function for parsing single file (for multiprocessing)"""
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
            'eventTime', 'eventTimeLocal', 'awsRegion', 'eventName', 'eventSource', 'sourceIpAddress',
            'userAgent', 'requestElements', 'responseElements'
        ]
        
        # Collect all userIdentity related columns
        user_identity_columns = [col for col in all_columns if col.startswith('userIdentity.')]
        user_identity_columns.sort()  # Sort alphabetically
        
        # Add userIdentity columns after main columns
        priority_columns.extend(user_identity_columns)
        
        # Add priority columns first, then sort remaining alphabetically
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
        
        # Add remaining columns sorted alphabetically
        remaining_columns = sorted(all_columns)
        ordered_columns.extend(remaining_columns)
        
        # Add sourceFile at the very end
        if source_file_removed:
            ordered_columns.append('sourceFile')
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=ordered_columns)
                writer.writeheader()
                
                # Use tqdm for progress bar when writing CSV
                for event in tqdm(events, desc="Writing CSV", unit="event"):
                    # Use value if exists, empty string if not for all columns
                    row = {col: event.get(col, '') for col in ordered_columns}
                    writer.writerow(row)
            
        except Exception as e:
            print(f"CSV save error: {e}")


def main():
    """Main execution function"""
    # Windows encoding setup
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    sys.stdout.reconfigure(encoding='utf-8')
    
    # Locale setup
    try:
        locale.setlocale(locale.LC_ALL, 'ko_KR.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'Korean_Korea.949')
        except:
            pass
    
    parser = CloudTrailParser()
    
    # Create directory structure
    result_dir = "result"
    parse_log_dir = os.path.join(result_dir, "parse_log")
    analysis_dir = os.path.join(result_dir, "analysis")
    report_dir = os.path.join(result_dir, "report")
    
    # Create directories
    os.makedirs(parse_log_dir, exist_ok=True)
    os.makedirs(analysis_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)
    
    # Usage example
    print("AWS CloudTrail Log Parser")
    print("=" * 50)
    
    # Input directory setting
    input_directory = r"C:\Users\kelly.jang\Desktop\새 폴더\AWS_LOG\CloudTrail Log (S3)"
    
    # Generate output filename with current time
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(parse_log_dir, f"cloudtrail_log_{current_time}.csv")
    
    print(f"Input directory: {input_directory}")
    print(f"Output file: {output_file}")
    
    # Log parsing
    print(f"\nParsing log files from directory: {input_directory}")
    events = parser.parse_directory(input_directory)
    
    if events:
        # Save to CSV
        print(f"\nSaving to CSV file: {output_file}")
        parser.save_to_csv(events, output_file)
    else:
        print("No events parsed.")


if __name__ == "__main__":
    main()
