#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS Log Parser Main Module
Integrated tool for parsing and analyzing AWS logs (CloudTrail, VPC Flow, S3 Access)
Cross-platform compatible (Windows, Linux, macOS)
"""

import os
import sys
import argparse
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import signal
from tqdm import tqdm
import logging

# Cross-platform encoding setup
if sys.platform.startswith('win'):
    # Windows encoding setup
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
else:
    # Linux/macOS encoding setup
    import locale
    try:
        locale.setlocale(locale.LC_ALL, '')
    except:
        pass

# Global logging setup
def setup_logging(output_path):
    """Setup logging to file and console"""
    # Create Result directory if it doesn't exist
    result_dir = os.path.join(output_path, 'Result')
    os.makedirs(result_dir, exist_ok=True)
    
    # Create log file path
    log_file = os.path.join(result_dir, 'log.txt')
    
    # Open log file for writing
    log_file_handle = open(log_file, 'w', encoding='utf-8')
    
    # Redirect stdout to both console and file
    original_stdout = sys.stdout
    sys.stdout = TeeOutput(original_stdout, log_file_handle)
    
    return log_file, log_file_handle

class TeeOutput:
    """Class to duplicate output to both console and log file"""
    def __init__(self, *files):
        self.files = files
    
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()
    
    def flush(self):
        for f in self.files:
            f.flush()

# Global flag for graceful shutdown
shutdown_requested = False

# Color codes (global)
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    BRIGHT_RED = '\033[1;91m'
    BRIGHT_GREEN = '\033[1;92m'
    BRIGHT_BLUE = '\033[1;94m'
    END = '\033[0m'

def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    global shutdown_requested
    print(f"\n\n[INTERRUPTED] Received signal {signum}. Shutting down gracefully...")
    shutdown_requested = True
    sys.exit(0)

# Import the individual parsers and analyzers
from cloudtrail_parser import CloudTrailParser
from vpc_parser import VPCFlowLogParser
from s3_parser import S3AccessLogParser
from cloudtrail_analyzer import CloudTrailAnalyzer
from vpc_analyzer import VPCFlowLogAnalyzer
from s3_analyzer import S3AccessLogAnalyzer

class AWSLogParserMain:
    """Main class for AWS Log Parser"""
    
    def __init__(self):
        self.parsers = {
            'cloudtrail': CloudTrailParser(),
            'vpc': VPCFlowLogParser(),
            's3': S3AccessLogParser()
        }
        
        self.analyzers = {
            'cloudtrail': None,  # Will be initialized when needed
            'vpc': None,
            's3': None
        }
    
    def run_parser(self, args):
        """Run the parser with given arguments"""
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")
        print(f"{Colors.CYAN}AWS Log Parser - Starting Analysis{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")
        
        # Track results
        analysis_results = {}
        total_events = 0
        successful_types = 0
        
        # Process each log type
        for log_type in ['cloudtrail', 'vpc', 's3']:
            log_path = getattr(args, log_type, None)
            if not log_path:
                print(f"\n{Colors.YELLOW}[SKIP]{Colors.END} Skipping {log_type.upper()} logs (no path provided)")
                continue
                
            print(f"\n{Colors.CYAN}[PROCESS]{Colors.END} Processing {log_type.upper()} logs from: {log_path}")
            
            try:
                # Parse logs
                parser = self.parsers[log_type]
                parsed_data = parser.parse_directory(log_path)
                
                if not parsed_data:
                    print(f"{Colors.RED}[ERROR]{Colors.END} No data found in {log_type.upper()} logs")
                    analysis_results[log_type] = {
                        'success': False,
                        'message': 'No data found'
                    }
                    continue
                
                total_events += len(parsed_data)
                
                # Create Result directory structure
                result_dir = os.path.join(args.output, 'Result')
                os.makedirs(result_dir, exist_ok=True)
                parse_logs_dir = os.path.join(result_dir, 'Parse_Logs')
                os.makedirs(parse_logs_dir, exist_ok=True)
                csv_file = os.path.join(parse_logs_dir, f"{log_type}_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
                
                # Convert parsed data to DataFrame and save as CSV with progress bar
                print(f"Converting {len(parsed_data):,} {log_type.upper()} events to DataFrame...")
                df = pd.DataFrame(parsed_data)
                
                print(f"Saving to CSV: {os.path.basename(csv_file)}")
                df.to_csv(csv_file, index=False)
                
                # Run analysis using the run_analysis function
                if log_type == 'cloudtrail':
                    from cloudtrail_analyzer import run_analysis
                elif log_type == 'vpc':
                    from vpc_analyzer import run_analysis
                elif log_type == 's3':
                    from s3_analyzer import run_analysis
                
                # Create Analysis_Logs and Report directories under Result
                analysis_logs_dir = os.path.join(result_dir, 'Analysis_Logs')
                report_dir = os.path.join(result_dir, 'Report')
                os.makedirs(analysis_logs_dir, exist_ok=True)
                os.makedirs(report_dir, exist_ok=True)
                
                analysis_file, html_file = run_analysis(csv_file, analysis_logs_dir, report_dir)
                
                analysis_result = {
                    'success': True,
                    'analysis_file': analysis_file,
                    'html_file': html_file
                }
                
                if analysis_result['success']:
                    print(f"{Colors.GREEN}[OK]{Colors.END} Analysis completed for {log_type.upper()}")
                    print(f"    Analysis file: {os.path.basename(analysis_result['analysis_file'])}")
                    print(f"    Report file: {os.path.basename(analysis_result['html_file'])}")
                    successful_types += 1
                else:
                    print(f"{Colors.RED}[ERROR]{Colors.END} Analysis failed for {log_type.upper()}: {analysis_result['message']}")
                
                analysis_results[log_type] = analysis_result
                
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.END} Error processing {log_type.upper()} logs: {str(e)}")
                analysis_results[log_type] = {
                    'success': False,
                    'message': f'Error: {str(e)}'
                }
        
        # Print summary
        print(f"\n{'=' * 60}")
        print("Analysis Summary")
        print('=' * 60)
        
        for log_type, result in analysis_results.items():
            print(f"\n{log_type.upper():<12} | ", end="")
            if result['success']:
                print(f"Analysis: {os.path.basename(result['analysis_file'])}")
                print(f"{'':<12} | Report: {os.path.basename(result['html_file'])}")
            else:
                print(f"Error: {result['message']}")
        print("-" * 60)
        
        print(f"Total successful log types: {successful_types}")
        print(f"Total parsed events: {total_events:,}")
        print("=" * 60)

        return 0

def print_logo():
    """Print ASCII art logo with colors (cross-platform)"""
    import os
    import sys
    
    def enable_colors():
        """Enable color support for different platforms"""
        if sys.platform.startswith('win'):
            # Windows color support
            try:
                import ctypes
                from ctypes import wintypes
                
                # Enable ANSI escape sequences on Windows 10+
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
                
                # Get current console mode
                mode = wintypes.DWORD()
                kernel32.GetConsoleMode(handle, ctypes.byref(mode))
                
                # Enable ANSI escape sequences
                mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, mode.value)
                return True
            except:
                return False
        else:
            # Linux/macOS - check if terminal supports colors
            return os.getenv('TERM') != 'dumb' and sys.stdout.isatty()
    
    # Check if colors are supported
    colors_supported = enable_colors()
    
    # Colors class is now global
    
    # Create logo with or without colors
    if colors_supported:
        logo = f"""
{Colors.CYAN}+===============================================================+{Colors.END}
{Colors.CYAN}|                                                               |{Colors.END}
{Colors.CYAN}   _      _  _   ______                                         {Colors.END}
{Colors.CYAN}  | |    (_)| |  | ___ \\                                       {Colors.END}
{Colors.CYAN}  | |__   _ | |_ | |_/ /  __ _  _ __  ___   ___  _ __           {Colors.END}
{Colors.CYAN}  | '_ \\ | || __||  __/  / _` || '__|/ __| / _ \\| '__|        {Colors.END}
{Colors.CYAN}  | |_) || || |_ | |    | (_| || |   \\__ \\|  __/| |           {Colors.END}
{Colors.CYAN}  |_.__/ |_| \\__|\\_|     \\__,_||_|   |___/ \\___||_|         {Colors.END}
{Colors.CYAN}                                                               {Colors.END}
{Colors.BLUE}  {Colors.BOLD}bitParser for AWS Log                            {Colors.END}
{Colors.CYAN}|                                                               |{Colors.END}
{Colors.CYAN}+===============================================================+{Colors.END}
        """
    else:
        # Fallback to plain text if colors are not supported
        logo = """
+===============================================================+
|                                                               |
   _      _  _   ______                                         
  | |    (_)| |  | ___ \                                        
  | |__   _ | |_ | |_/ /  __ _  _ __  ___   ___  _ __           
  | '_ \ | || __||  __/  / _` || '__|/ __| / _ \| '__|          
  | |_) || || |_ | |    | (_| || |   \__ \|  __/| |             
  |_.__/ |_| \__|\_|     \__,_||_|   |___/ \___||_|            
                                                               
  bitParser for AWS Log                                         
|                                                               |
+===============================================================+
        """
    
    print(logo)

def clear_screen():
    """Clear the screen (cross-platform)"""
    import subprocess
    import sys
    
    if sys.platform.startswith('win'):
        os.system('cls')
    else:
        # Use subprocess for better cross-platform compatibility
        try:
            subprocess.run(['clear'], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to print newlines if clear command fails
            print('\n' * 50)

def get_input_with_prompt(prompt):
    """Function to get user input"""
    while True:
        try:
            user_input = input(f"{prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[INTERRUPTED] Input interrupted.")
            try:
                print("Press Ctrl+Z (or Ctrl+C) again to exit, or press Enter to continue...")
                confirm_exit = input("").strip()
                # If user presses Enter (empty input), continue
                print("Continuing...")
                continue
            except (EOFError, KeyboardInterrupt):
                print("\nExiting program...")
                sys.exit(0)
        
        if not user_input:
            print("Please enter a path or (N) if no logs available.")
            continue
            
        # Check if user wants to skip
        if user_input.upper() == 'N':
            return None
        
        # Path normalization (cross-platform)
        path = os.path.normpath(os.path.expanduser(user_input))
        
        # Check if directory exists
        if os.path.exists(path):
            return path
        else:
            print(f"Path does not exist: {path}")
            try:
                retry = input("Would you like to try again? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[INTERRUPTED] Input interrupted.")
                try:
                    confirm_exit = input("Are you sure you want to exit the program? (y/n): ").strip().lower()
                    if confirm_exit in ['y', 'yes']:
                        print("Exiting program...")
                        sys.exit(0)
                    else:
                        print("Continuing...")
                        continue
                except (EOFError, KeyboardInterrupt):
                    print("\nExiting program...")
                    sys.exit(0)
            if retry != 'y':
                return None

def get_output_path():
    """Function to get output path"""
    while True:
        try:
            user_input = input("Output Folder Path: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[INTERRUPTED] Input interrupted.")
            try:
                print("Press Ctrl+Z (or Ctrl+C) again to exit, or press Enter to continue...")
                confirm_exit = input("").strip()
                # If user presses Enter (empty input), continue
                print("Continuing...")
                continue
            except (EOFError, KeyboardInterrupt):
                print("\nExiting program...")
                sys.exit(0)
        
        if not user_input:
            print("Please enter a path or (N) if no output needed.")
            continue
        
        path = os.path.normpath(os.path.expanduser(user_input))
        
        # Ask if directory should be created if it doesn't exist
        if not os.path.exists(path):
            try:
                create = input(f"Directory does not exist. Would you like to create it? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[INTERRUPTED] Input interrupted.")
                try:
                    confirm_exit = input("Are you sure you want to exit the program? (y/n): ").strip().lower()
                    if confirm_exit in ['y', 'yes']:
                        print("Exiting program...")
                        sys.exit(0)
                    else:
                        print("Continuing...")
                        continue
                except (EOFError, KeyboardInterrupt):
                    print("\nExiting program...")
                    sys.exit(0)
            if create == 'y':
                try:
                    os.makedirs(path, exist_ok=True)
                    print(f"Directory created: {path}")
                    return path
                except Exception as e:
                    print(f"Failed to create directory: {e}")
                    continue
            else:
                continue
        else:
            return path

def main():
    """Main function with interactive input"""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)  # SIGTERM
    
    try:
        clear_screen()
        print_logo()
        
        # Get output path first for logging setup
        output_path = get_output_path()
        if not output_path:
            print(f"{Colors.RED}[ERROR]{Colors.END} Output path is required.")
            return 1
        
        # Setup logging
        log_file, log_file_handle = setup_logging(output_path)
        
        # Store input paths
        paths = {}
        
        # CloudTrail log path
        cloudtrail_path = get_input_with_prompt("CloudTrail Log Folder Path")
        if cloudtrail_path:
            paths['cloudtrail'] = cloudtrail_path
            print(f"{Colors.GREEN}[OK]{Colors.END} CloudTrail path set: {cloudtrail_path}")
        else:
            print(f"{Colors.YELLOW}[SKIP]{Colors.END} Skipping CloudTrail path.")
        
        # VPC Flow log path
        vpc_path = get_input_with_prompt("VPC Flow Log Folder Path")
        if vpc_path:
            paths['vpc'] = vpc_path
            print(f"{Colors.GREEN}[OK]{Colors.END} VPC Flow path set: {vpc_path}")
        else:
            print(f"{Colors.YELLOW}[SKIP]{Colors.END} Skipping VPC Flow path.")
        
        # S3 Access log path
        s3_path = get_input_with_prompt("S3 Server Access Log Folder Path")
        if s3_path:
            paths['s3'] = s3_path
            print(f"{Colors.GREEN}[OK]{Colors.END} S3 Access path set: {s3_path}")
        else:
            print(f"{Colors.YELLOW}[SKIP]{Colors.END} Skipping S3 Access path.")
        
        paths['output'] = output_path
        print(f"{Colors.GREEN}[OK]{Colors.END} Output path set: {output_path}")
        
        # Configuration confirmation
        print("\n" + "="*60)
        print("Configuration Summary")
        print("="*60)
        
        if 'cloudtrail' in paths:
            print(f"CloudTrail: {paths['cloudtrail']}")
        if 'vpc' in paths:
            print(f"VPC Flow: {paths['vpc']}")
        if 's3' in paths:
            print(f"S3 Access: {paths['s3']}")
        print(f"Output: {paths['output']}")
        
        # Analysis execution confirmation
        print("\n" + "-"*60)
        try:
            confirm = input("Would you like to start the analysis? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[INTERRUPTED] Input interrupted.")
            try:
                confirm_exit = input("Are you sure you want to exit the program? (y/n): ").strip().lower()
                if confirm_exit in ['y', 'yes']:
                    print("Exiting program...")
                    sys.exit(0)
                else:
                    print("Continuing...")
                    # Restart by calling main function again
                    return main()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting program...")
                sys.exit(0)
        
        if confirm == 'y':
            print("\n[START] Starting analysis...")
            
            # Create argparse.Namespace object for compatibility
            class Args:
                def __init__(self, paths):
                    self.cloudtrail = paths.get('cloudtrail')
                    self.vpc = paths.get('vpc')
                    self.s3 = paths.get('s3')
                    self.output = paths['output']  # Use the original output path
            
            args = Args(paths)
            
            # Run the parser
            parser = AWSLogParserMain()
            result = parser.run_parser(args)
            
            print("\n[COMPLETE] Analysis completed!")
            print(f"Result files location: {paths['output']}")
            
            # Close log file
            log_file_handle.close()
            # Restore original stdout
            sys.stdout = sys.stdout.files[0]
            
            return result
        else:
            print("\n[CANCEL] Analysis cancelled.")
            
            # Close log file
            log_file_handle.close()
            # Restore original stdout
            sys.stdout = sys.stdout.files[0]
            
            return 0

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Program interrupted by user (Ctrl+C)")
        print("Exiting...")
        
        # Close log file if it exists
        try:
            log_file_handle.close()
            sys.stdout = sys.stdout.files[0]
        except:
            pass
        
        return 1
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")
        
        # Close log file if it exists
        try:
            log_file_handle.close()
            sys.stdout = sys.stdout.files[0]
        except:
            pass
        
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error occurred: {str(e)}")
        sys.exit(1)